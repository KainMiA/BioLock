"""
Tests for the BioLock core modules (no Streamlit needed).

Run from the BioLockApp_20260309 directory:
    python -m unittest discover -s tests -v
"""

import io
import os
import sys
import json
import base64
import hashlib
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth_manager  # noqa: E402
import file_storage  # noqa: E402
from auth_manager import AuthError, UserManager  # noqa: E402
from file_storage import FileStorageManager, StorageError, resolve_custom_key  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

PASSWORD = "Secret123"
MIB = 1024 * 1024


class FastKdf(unittest.TestCase):
    """Lower the PBKDF2 iteration counts so the suite runs quickly"""

    def setUp(self):
        patches = [
            mock.patch.object(auth_manager, 'PBKDF2_ITERATIONS', 1000),
            mock.patch.object(file_storage, 'PASSPHRASE_ITERATIONS', 1000),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)


class UserManagerTests(FastKdf):

    def setUp(self):
        super().setUp()
        self.users = UserManager(str(self.base / "users"))
        self.recovery = self.users.create_user("alice", PASSWORD, "alice@example.com", "Alice A")

    def user_json(self, name="alice"):
        return json.loads((self.base / "users" / f"{name}.json").read_text())

    def test_master_key_not_stored_in_plain(self):
        profile, master = self.users.authenticate_user("alice", PASSWORD)
        self.assertEqual(profile['email'], "alice@example.com")
        self.assertEqual(len(master), 32)
        raw = (self.base / "users" / "alice.json").read_text()
        self.assertNotIn("derived_key", raw)
        self.assertNotIn(base64.b64encode(master).decode(), raw)

    def test_wrong_password(self):
        self.assertIsNone(self.users.authenticate_user("alice", "Wrong1234"))
        self.assertIsNone(self.users.authenticate_user("nobody", PASSWORD))

    def test_duplicates_rejected(self):
        with self.assertRaises(AuthError):
            self.users.create_user("ALICE", PASSWORD, "other@example.com", "x")
        with self.assertRaises(AuthError):
            self.users.create_user("bob", PASSWORD, "Alice@Example.com", "x")

    def test_invalid_input_rejected(self):
        for bad in ["../evil", "a", "with space", "x" * 40, "a/b"]:
            with self.assertRaises(AuthError):
                self.users.create_user(bad, PASSWORD, "e@example.com", "x")
        with self.assertRaises(AuthError):
            self.users.create_user("bob", "weak", "bob@example.com", "x")
        with self.assertRaises(AuthError):
            self.users.create_user("bob", "A1" + "a" * 80, "bob@example.com", "x")
        self.assertFalse((self.base / "evil.json").exists())

    def test_change_password_keeps_master_key(self):
        _, master = self.users.authenticate_user("alice", PASSWORD)
        with self.assertRaises(AuthError):
            self.users.change_password("alice", "Wrong1234", "NewSecret456")
        with self.assertRaises(AuthError):
            self.users.change_password("alice", "", "NewSecret456")
        self.users.change_password("alice", PASSWORD, "NewSecret456")
        self.assertIsNone(self.users.authenticate_user("alice", PASSWORD))
        _, master2 = self.users.authenticate_user("alice", "NewSecret456")
        self.assertEqual(master, master2)

    def test_reset_with_recovery_key_keeps_master_key(self):
        _, master = self.users.authenticate_user("alice", PASSWORD)
        username, code = self.users.request_password_reset("ALICE@example.com")
        self.assertEqual(username, "alice")
        with self.assertRaises(AuthError):
            self.users.reset_password("alice", code, "NewSecret456", SecretKey())
        preserved, new_recovery = self.users.reset_password("alice", code, "NewSecret456", self.recovery)
        self.assertTrue(preserved)
        self.assertIsNone(new_recovery)
        _, master2 = self.users.authenticate_user("alice", "NewSecret456")
        self.assertEqual(master, master2)
        # the code is single-use
        with self.assertRaises(AuthError):
            self.users.reset_password("alice", code, "Another789A")

    def test_reset_without_recovery_key_creates_new_key(self):
        _, master = self.users.authenticate_user("alice", PASSWORD)
        _, code = self.users.request_password_reset("alice@example.com")
        preserved, new_recovery = self.users.reset_password("alice", code, "NewSecret456")
        self.assertFalse(preserved)
        self.assertTrue(new_recovery)
        _, master2 = self.users.authenticate_user("alice", "NewSecret456")
        self.assertNotEqual(master, master2)
        # the new recovery key works for the next reset
        _, code = self.users.request_password_reset("alice@example.com")
        preserved, _ = self.users.reset_password("alice", code, "Third789Abc", new_recovery)
        self.assertTrue(preserved)

    def test_reset_code_attempt_limit(self):
        _, code = self.users.request_password_reset("alice@example.com")
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(auth_manager.RESET_CODE_MAX_ATTEMPTS):
            with self.assertRaises(AuthError):
                self.users.reset_password("alice", wrong, "NewSecret456")
        with self.assertRaises(AuthError):
            self.users.reset_password("alice", code, "NewSecret456")
        self.assertIsNone(self.users.request_password_reset("nobody@example.com"))

    def test_regenerate_recovery_key(self):
        with self.assertRaises(AuthError):
            self.users.regenerate_recovery_key("alice", "Wrong1234")
        new_key = self.users.regenerate_recovery_key("alice", PASSWORD)
        _, code = self.users.request_password_reset("alice@example.com")
        with self.assertRaises(AuthError):
            self.users.reset_password("alice", code, "NewSecret456", self.recovery)
        preserved, _ = self.users.reset_password("alice", code, "NewSecret456", new_key)
        self.assertTrue(preserved)

    def test_profile_update(self):
        self.users.create_user("bob", PASSWORD, "bob@example.com", "Bob")
        with self.assertRaises(AuthError):
            self.users.update_user_profile("alice", "Alice", "bob@example.com")
        profile = self.users.update_user_profile("alice", "Alice B", "alice2@example.com")
        self.assertEqual(profile['email'], "alice2@example.com")
        self.assertEqual(self.users.get_profile("alice")['full_name'], "Alice B")

    def test_legacy_account_is_migrated(self):
        # An account as written by the original BioLock version
        salt = secrets.token_bytes(16)
        legacy_key = auth_manager.derive_key("Legacy123", salt, 100_000)
        legacy = {
            'username': 'legacy',
            'email': 'legacy@example.com',
            'full_name': 'Legacy User',
            'password_hash': UserManager.hash_password("Legacy123"),
            'key_salt': base64.b64encode(salt).decode(),
            'derived_key': base64.b64encode(legacy_key).decode(),
            'created': '2026-03-09T10:00:00',
            'last_login': None
        }
        (self.base / "users" / "legacy.json").write_text(json.dumps(legacy))

        _, master = self.users.authenticate_user("legacy", "Legacy123")
        self.assertEqual(master, legacy_key)
        stored = self.user_json("legacy")
        self.assertNotIn('derived_key', stored)
        self.assertIn('wrapped_master_key', stored)
        self.assertFalse(self.users.has_recovery_key("legacy"))
        # still the same key on the next login
        _, master2 = self.users.authenticate_user("legacy", "Legacy123")
        self.assertEqual(master2, legacy_key)


def SecretKey():
    return base64.b64encode(secrets.token_bytes(32)).decode()


class StorageTests(FastKdf):

    def setUp(self):
        super().setUp()
        self.storage = FileStorageManager(str(self.base))
        self.key = secrets.token_bytes(32)
        self.data = os.urandom(int(2.5 * MIB))

    def store(self, data=None, key=None, key_info=None, slice_mb=1, name="sample.bin", user="alice"):
        data = self.data if data is None else data
        return self.storage.store_file(io.BytesIO(data), name, user, slice_mb=slice_mb,
                                       key=key, key_info=key_info, total_size=len(data))

    def restore(self, file_id, key=None, user="alice", name="out.bin", **kwargs):
        out = self.base / "restored" / name
        self.storage.restore_file(file_id, user, str(out), key=key, **kwargs)
        return out.read_bytes()

    def test_plain_roundtrip(self):
        result = self.store()
        self.assertEqual(result['slices'], 3)
        self.assertFalse(result['encrypted'])
        self.assertEqual(self.restore(result['file_id']), self.data)

    def test_encrypted_roundtrip_and_no_plaintext_hashes(self):
        result = self.store(key=self.key, key_info={'key_source': 'password', 'key_mode': 'raw'})
        self.assertTrue(result['encrypted'])
        index_text = (self.base / "indexes" / f"{result['file_id']}.json").read_text()
        self.assertNotIn(hashlib.sha256(self.data).hexdigest(), index_text)
        self.assertNotIn(hashlib.sha256(self.data[:MIB]).hexdigest(), index_text)
        for path in (self.base / "storage").iterdir():
            self.assertNotIn(self.data[:64], path.read_bytes())
        self.assertEqual(self.restore(result['file_id'], key=self.key), self.data)

    def test_edge_sizes(self):
        for size in (0, 1, MIB, 2 * MIB, 2 * MIB + 1):
            data = os.urandom(size)
            for key in (None, self.key):
                result = self.store(data=data, key=key)
                self.assertEqual(result['size'], size)
                self.assertEqual(self.restore(result['file_id'], key=key, name=f"o{size}{key is None}"), data)

    def test_stream_is_rewound(self):
        stream = io.BytesIO(self.data)
        stream.read()  # e.g. a previous Streamlit rerun consumed it
        result = self.storage.store_file(stream, "s.bin", "alice", slice_mb=1)
        self.assertEqual(result['size'], len(self.data))

    def test_wrong_key_and_missing_key(self):
        result = self.store(key=self.key)
        with self.assertRaises(StorageError):
            self.restore(result['file_id'], key=secrets.token_bytes(32))
        with self.assertRaises(StorageError):
            self.restore(result['file_id'], key=None)
        self.assertFalse((self.base / "restored" / "out.bin").exists())

    def test_other_user_cannot_restore(self):
        result = self.store()
        with self.assertRaises(StorageError):
            self.restore(result['file_id'], user="mallory")
        self.assertEqual(self.storage.get_user_files("mallory"), [])
        self.assertEqual(len(self.storage.get_user_files("alice")), 1)

    def test_custom_raw_key_and_passphrase(self):
        raw_text = SecretKey()
        key, info = resolve_custom_key(raw_text)
        self.assertEqual(info['key_mode'], 'raw')
        result = self.store(key=key, key_info=info)
        key2 = self.storage.resolve_restore_key(result['file_id'], "alice", custom_key=raw_text)
        self.assertEqual(self.restore(result['file_id'], key=key2), self.data)

        key, info = resolve_custom_key("correct horse battery")
        self.assertEqual(info['key_mode'], 'passphrase')
        result = self.store(key=key, key_info=info)
        with self.assertRaises(StorageError):
            self.storage.resolve_restore_key(result['file_id'], "alice", custom_key="wrong passphrase")
        key2 = self.storage.resolve_restore_key(result['file_id'], "alice", custom_key="correct horse battery")
        self.assertEqual(self.restore(result['file_id'], key=key2, name="p.bin"), self.data)

        with self.assertRaises(StorageError):
            resolve_custom_key("short")

    def test_password_key_resolution(self):
        result = self.store(key=self.key, key_info={'key_source': 'password', 'key_mode': 'raw'})
        key = self.storage.resolve_restore_key(result['file_id'], "alice", master_key=self.key)
        self.assertEqual(key, self.key)
        with self.assertRaises(StorageError):
            self.storage.resolve_restore_key(result['file_id'], "alice", master_key=secrets.token_bytes(32))

    def _slice_path(self, file_id, n, suffix=".enc"):
        return self.base / "storage" / f"{file_id}_slice{n:06d}{suffix}"

    def test_tampering_detected(self):
        result = self.store(key=self.key)
        path = self._slice_path(result['file_id'], 1)
        blob = bytearray(path.read_bytes())
        blob[100] ^= 1
        path.write_bytes(bytes(blob))
        with self.assertRaises(StorageError):
            self.restore(result['file_id'], key=self.key)
        self.assertEqual(list((self.base / "restored").glob("*")), [])

    def test_reordering_detected_even_with_edited_index(self):
        result = self.store(key=self.key)
        file_id = result['file_id']
        p0, p1 = self._slice_path(file_id, 0), self._slice_path(file_id, 1)
        b0, b1 = p0.read_bytes(), p1.read_bytes()
        p0.write_bytes(b1)
        p1.write_bytes(b0)
        index = self.storage._indexes[file_id]
        index['slices'][0]['cipher_hash'], index['slices'][1]['cipher_hash'] = (
            index['slices'][1]['cipher_hash'], index['slices'][0]['cipher_hash'])
        with self.assertRaises(StorageError):
            self.restore(file_id, key=self.key)

    def test_truncation_detected_even_with_edited_index(self):
        result = self.store(key=self.key)
        file_id = result['file_id']
        index = self.storage._indexes[file_id]
        dropped = index['slices'].pop()
        index['total_slices'] -= 1
        index['file_info']['size'] -= dropped['size']
        with self.assertRaises(StorageError):
            self.restore(file_id, key=self.key)

    def test_overwrite_protection(self):
        result = self.store()
        self.restore(result['file_id'])
        with self.assertRaises(StorageError):
            self.restore(result['file_id'])
        self.assertEqual(self.restore(result['file_id'], overwrite=True), self.data)

    def test_failed_store_leaves_no_slices(self):
        class Broken(io.BytesIO):
            def read(self, size=-1):
                if self.tell() >= MIB:
                    raise OSError("disk error")
                return super().read(size)

        with self.assertRaises(OSError):
            self.storage.store_file(Broken(self.data), "b.bin", "alice", slice_mb=1)
        self.assertEqual(list((self.base / "storage").iterdir()), [])
        self.assertEqual(list((self.base / "indexes").iterdir()), [])

    def test_invalid_slice_size(self):
        for size in (0, 501):
            with self.assertRaises(StorageError):
                self.store(slice_mb=size)

    def test_indexes_reload_from_disk(self):
        result = self.store(key=self.key)
        fresh = FileStorageManager(str(self.base))
        out = self.base / "fresh.bin"
        fresh.restore_file(result['file_id'], "alice", str(out), key=self.key)
        self.assertEqual(out.read_bytes(), self.data)

    def write_legacy_file(self, data, key_b64=None, slice_size=MIB):
        """Write a file exactly like the original BioLock version did"""
        upload_id = "1741500000_abcdef12"
        slices = []
        for i in range(0, max(len(data), 1), slice_size):
            chunk = data[i:i + slice_size]
            n = len(slices)
            slice_id = f"{upload_id}_slice{n:04d}"
            if key_b64:
                aes = AESGCM(base64.b64decode(key_b64))
                nonce = secrets.token_bytes(12)
                (self.base / "storage" / f"{slice_id}.enc").write_text(json.dumps({
                    'data': base64.b64encode(aes.encrypt(nonce, chunk, b"")).decode(),
                    'nonce': base64.b64encode(nonce).decode()
                }))
            else:
                (self.base / "storage" / slice_id).write_bytes(chunk)
            slices.append({'index': n, 'id': slice_id, 'size': len(chunk),
                           'hash': hashlib.sha256(chunk).hexdigest(), 'encrypted': bool(key_b64)})
        file_hash = hashlib.sha256(data).hexdigest()
        index = {
            'file_id': f"{file_hash[:16]}_1741500000",
            'file_info': {'name': 'legacy.bin', 'size': len(data), 'hash': file_hash,
                          'type': 'application/octet-stream'},
            'slice_size': slice_size,
            'total_slices': len(slices),
            'slices': slices,
            'created': '2026-03-09T10:00:00',
            'encrypted': bool(key_b64),
            'username': 'alice'
        }
        (self.base / "indexes" / f"{index['file_id']}.json").write_text(json.dumps(index))
        return index['file_id']

    def test_legacy_files_still_restore(self):
        key_b64 = SecretKey()
        enc_id = self.write_legacy_file(self.data, key_b64)
        storage = FileStorageManager(str(self.base))
        key = storage.resolve_restore_key(enc_id, "alice", custom_key=key_b64)
        out = self.base / "legacy_enc.bin"
        storage.restore_file(enc_id, "alice", str(out), key=key)
        self.assertEqual(out.read_bytes(), self.data)

        with self.assertRaises(StorageError):
            storage.restore_file(enc_id, "alice", str(self.base / "x.bin"), key=secrets.token_bytes(32))

    def test_legacy_plain_file_restores(self):
        for p in (self.base / "indexes").glob("*"):
            p.unlink()
        plain_id = self.write_legacy_file(self.data)
        storage = FileStorageManager(str(self.base))
        out = self.base / "legacy_plain.bin"
        storage.restore_file(plain_id, "alice", str(out))
        self.assertEqual(out.read_bytes(), self.data)


class EndToEndTests(FastKdf):
    """Password key survives a password change and still decrypts stored files"""

    def test_password_change_keeps_files_readable(self):
        users = UserManager(str(self.base / "users"))
        storage = FileStorageManager(str(self.base))
        users.create_user("carol", PASSWORD, "carol@example.com", "Carol")
        _, master = users.authenticate_user("carol", PASSWORD)
        data = os.urandom(300_000)
        result = storage.store_file(io.BytesIO(data), "c.bin", "carol", slice_mb=1, key=master,
                                    key_info={'key_source': 'password', 'key_mode': 'raw'})

        users.change_password("carol", PASSWORD, "Changed789X")
        _, master_after = users.authenticate_user("carol", "Changed789X")
        key = storage.resolve_restore_key(result['file_id'], "carol", master_key=master_after)
        out = self.base / "c_out.bin"
        storage.restore_file(result['file_id'], "carol", str(out), key=key)
        self.assertEqual(out.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
