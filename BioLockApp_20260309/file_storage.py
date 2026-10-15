"""
File Storage Manager

Storage layout (format version 2)
---------------------------------
* ``indexes/<file_id>.json``                index file (metadata + slice list)
* ``storage/<file_id>_slice<NNNNNN>.enc``   encrypted slice: nonce (12 bytes) || AES-256-GCM ciphertext+tag
* ``storage/<file_id>_slice<NNNNNN>.bin``   plain slice (encryption disabled)

Every encrypted slice is authenticated together with its file id, its
position and whether it is the last slice, so slices cannot be swapped,
reordered, or dropped from the end without detection. Indexes of encrypted
files contain no hashes of the plaintext (those would let anyone confirm a
guess of the file's content); they store a hash of the stored ciphertext
instead, plus a key check value so a wrong key is reported clearly.

Indexes written by older BioLock versions (no ``format_version``) can still be
restored.

This module has no Streamlit dependency so it can be tested on its own.
"""

import os
import re
import json
import uuid
import base64
import hashlib
import hmac
import secrets
import threading
from pathlib import Path
from datetime import datetime
from typing import BinaryIO, Callable, Dict, Iterator, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auth_manager import derive_key
from utils import atomic_write_json, decode_raw_key

FORMAT_VERSION = 2
NONCE_SIZE = 12
MIB = 1024 * 1024
MIN_SLICE_MB = 1
MAX_SLICE_MB = 500
PASSPHRASE_ITERATIONS = 600_000
MIN_PASSPHRASE_LENGTH = 8
KEY_CHECK_CONTEXT = b"BioLock key check v1"
SAFE_ID_PATTERN = re.compile(r'^[A-Za-z0-9_]+$')

ProgressCallback = Optional[Callable[[int, int], None]]


class StorageError(Exception):
    """Raised with a user-facing message when storing or restoring fails"""


def key_check_value(key: bytes) -> str:
    """A value that identifies a key without revealing it"""
    return hmac.new(key, KEY_CHECK_CONTEXT, hashlib.sha256).hexdigest()[:32]


def _slice_aad(file_id: str, index: int, is_last: bool) -> bytes:
    return f"BioLock|v{FORMAT_VERSION}|{file_id}|{index}|{'last' if is_last else 'more'}".encode()


def resolve_custom_key(text: str) -> Tuple[bytes, Dict]:
    """Turn a user supplied custom key into an AES-256 key for storing a file.

    A base64 256-bit key (as generated on the Keys page) is used as is; anything
    else is treated as a passphrase and run through PBKDF2 with a per-file salt.
    """
    raw = decode_raw_key(text)
    if raw is not None:
        return raw, {'key_source': 'custom', 'key_mode': 'raw'}

    if not text or len(text) < MIN_PASSPHRASE_LENGTH:
        raise StorageError(
            f"A custom key must be a generated key or a passphrase of at least "
            f"{MIN_PASSPHRASE_LENGTH} characters")

    salt = secrets.token_bytes(16)
    key = derive_key(text, salt, PASSPHRASE_ITERATIONS)
    return key, {
        'key_source': 'custom',
        'key_mode': 'passphrase',
        'salt': base64.b64encode(salt).decode('ascii'),
        'iterations': PASSPHRASE_ITERATIONS
    }


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Read up to ``size`` bytes, looping because read() may return less"""
    parts = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _iter_slices(stream: BinaryIO, slice_size: int) -> Iterator[Tuple[bytes, bool]]:
    """Yield (slice, is_last). An empty input yields a single empty slice."""
    current = _read_exact(stream, slice_size)
    if not current:
        yield b"", True
        return
    while current:
        following = _read_exact(stream, slice_size)
        yield current, not following
        current = following


class FileStorageManager:
    """File storage manager with streaming, chunked storage.

    One instance is shared by all Streamlit sessions.
    """

    def __init__(self, base_dir: str = "."):
        base = Path(base_dir)
        self.storage_dir = base / "storage"
        self.index_dir = base / "indexes"

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._indexes: Dict[str, Dict] = self._load_indexes()

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------

    def _load_indexes(self) -> Dict:
        """Load all indexes from disk"""
        indexes = {}
        for index_file in self.index_dir.glob("*.json"):
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
                file_id = index_data['file_id']
                index_data['file_info']['name']
                index_data['slices']
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if SAFE_ID_PATTERN.match(str(file_id)):
                indexes[file_id] = index_data
        return indexes

    def _save_index(self, index_data: Dict):
        atomic_write_json(self.index_dir / f"{index_data['file_id']}.json", index_data)
        with self._lock:
            self._indexes[index_data['file_id']] = index_data

    def get_index(self, file_id: str, username: str) -> Dict:
        with self._lock:
            index_data = self._indexes.get(file_id)
        if not index_data or index_data.get('username') != username:
            raise StorageError("File not found")
        return index_data

    def get_user_files(self, username: str) -> List[Dict]:
        """Get files for a user, newest first"""
        with self._lock:
            indexes = list(self._indexes.values())

        user_files = []
        for index_data in indexes:
            if index_data.get('username') != username:
                continue
            encryption = index_data.get('encryption') or {}
            user_files.append({
                'id': index_data['file_id'],
                'name': index_data['file_info']['name'],
                'size': index_data['file_info']['size'],
                'created': index_data.get('created', ''),
                'encrypted': bool(index_data.get('encrypted')),
                'key_source': encryption.get('key_source'),
                'slices': index_data.get('total_slices', len(index_data['slices']))
            })

        user_files.sort(key=lambda x: x['created'], reverse=True)
        return user_files

    def get_storage_stats(self, username: Optional[str] = None) -> Dict:
        """Get storage statistics (for one user, or for everybody)"""
        with self._lock:
            indexes = [i for i in self._indexes.values()
                       if username is None or i.get('username') == username]
        return {
            'total_files': len(indexes),
            'total_size': sum(i['file_info']['size'] for i in indexes),
            'encrypted_files': sum(1 for i in indexes if i.get('encrypted'))
        }

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store_file(self, file_stream: BinaryIO, filename: str, username: str,
                   slice_mb: int = 10, key: Optional[bytes] = None,
                   key_info: Optional[Dict] = None, total_size: Optional[int] = None,
                   progress_callback: ProgressCallback = None) -> Dict:
        """Split a stream into slices, encrypt them if a key is given, and write an index.

        Only one or two slices are held in memory at a time, so files larger
        than RAM can be stored.
        """
        if not MIN_SLICE_MB <= int(slice_mb) <= MAX_SLICE_MB:
            raise StorageError(f"Slice size must be between {MIN_SLICE_MB} and {MAX_SLICE_MB} MB")
        if key is not None and len(key) != 32:
            raise StorageError("Encryption key must be 256 bits")

        filename = Path(str(filename).replace('\\', '/')).name or "unnamed"
        key_info = dict(key_info or {'key_source': 'custom', 'key_mode': 'raw'})

        # Streamlit's UploadedFile keeps its position between reruns
        if hasattr(file_stream, 'seek'):
            try:
                file_stream.seek(0)
            except (OSError, ValueError):
                pass

        file_id = uuid.uuid4().hex
        slice_size = int(slice_mb) * MIB
        aesgcm = AESGCM(key) if key is not None else None
        plain_hash = hashlib.sha256()
        slices_info = []
        written_paths: List[Path] = []
        bytes_processed = 0

        try:
            for slice_index, (chunk, is_last) in enumerate(_iter_slices(file_stream, slice_size)):
                slice_id = f"{file_id}_slice{slice_index:06d}"

                if aesgcm is not None:
                    nonce = secrets.token_bytes(NONCE_SIZE)
                    blob = nonce + aesgcm.encrypt(
                        nonce, chunk, _slice_aad(file_id, slice_index, is_last))
                    slice_path = self.storage_dir / f"{slice_id}.enc"
                    slice_info = {
                        'index': slice_index,
                        'id': slice_id,
                        'size': len(chunk),
                        'stored_size': len(blob),
                        'cipher_hash': hashlib.sha256(blob).hexdigest()
                    }
                else:
                    blob = chunk
                    plain_hash.update(chunk)
                    slice_path = self.storage_dir / f"{slice_id}.bin"
                    slice_info = {
                        'index': slice_index,
                        'id': slice_id,
                        'size': len(chunk),
                        'hash': hashlib.sha256(chunk).hexdigest()
                    }

                with open(slice_path, 'xb') as slice_file:
                    written_paths.append(slice_path)
                    slice_file.write(blob)

                slices_info.append(slice_info)
                bytes_processed += len(chunk)

                if progress_callback:
                    progress_callback(bytes_processed, max(total_size or 0, bytes_processed))

            index_data = {
                'format_version': FORMAT_VERSION,
                'file_id': file_id,
                'file_info': {
                    'name': filename,
                    'size': bytes_processed,
                    'hash': None if aesgcm is not None else plain_hash.hexdigest(),
                    'type': 'application/octet-stream'
                },
                'slice_size': slice_size,
                'total_slices': len(slices_info),
                'slices': slices_info,
                'created': datetime.now().isoformat(),
                'encrypted': aesgcm is not None,
                'encryption': None,
                'username': username
            }
            if aesgcm is not None:
                index_data['encryption'] = {
                    'algorithm': 'AES-256-GCM',
                    'key_check': key_check_value(key),
                    **key_info
                }

            self._save_index(index_data)

        except BaseException:
            # Do not leave orphaned slices behind
            for path in written_paths:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise

        return {
            'file_id': file_id,
            'name': filename,
            'size': bytes_processed,
            'encrypted': aesgcm is not None,
            'slices': len(slices_info),
            'created': index_data['created']
        }

    def store_large_file(self, file_path: str, username: str, slice_mb: int = 10,
                         key: Optional[bytes] = None, key_info: Optional[Dict] = None,
                         progress_callback: ProgressCallback = None) -> Dict:
        """Store a file directly from a path on this machine"""
        if not os.path.isfile(file_path):
            raise StorageError(f"File not found: {file_path}")
        with open(file_path, 'rb') as f:
            return self.store_file(
                file_stream=f,
                filename=os.path.basename(file_path),
                username=username,
                slice_mb=slice_mb,
                key=key,
                key_info=key_info,
                total_size=os.path.getsize(file_path),
                progress_callback=progress_callback
            )

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------

    @staticmethod
    def is_legacy(index_data: Dict) -> bool:
        return 'format_version' not in index_data

    def resolve_restore_key(self, file_id: str, username: str,
                            master_key: Optional[bytes] = None,
                            custom_key: Optional[str] = None) -> bytes:
        """Work out the decryption key from the user's choice and check it"""
        index_data = self.get_index(file_id, username)
        if not index_data.get('encrypted'):
            raise StorageError("This file is not encrypted")

        if self.is_legacy(index_data):
            if custom_key:
                try:
                    key = base64.b64decode(''.join(custom_key.split()))
                except ValueError:
                    raise StorageError("The decryption key is not valid base64")
            elif master_key:
                key = master_key
            else:
                raise StorageError("A decryption key is required")
            if len(key) not in (16, 24, 32):
                raise StorageError("The decryption key has an invalid length")
            return key  # legacy indexes have no key check; slices are verified on decrypt

        encryption = index_data.get('encryption') or {}
        if custom_key:
            if encryption.get('key_mode') == 'passphrase':
                key = derive_key(custom_key, base64.b64decode(encryption['salt']),
                                 int(encryption.get('iterations', PASSPHRASE_ITERATIONS)))
            else:
                key = decode_raw_key(custom_key)
                if key is None:
                    raise StorageError("The decryption key is not a valid 256-bit base64 key")
        elif master_key:
            key = master_key
        else:
            raise StorageError("A decryption key is required")

        if not hmac.compare_digest(key_check_value(key), encryption.get('key_check', '')):
            raise StorageError("Wrong decryption key for this file")
        return key

    def _slice_path(self, slice_id: str, suffix: str) -> Path:
        if not SAFE_ID_PATTERN.match(str(slice_id)):
            raise StorageError("Index contains an invalid slice id")
        return self.storage_dir / f"{slice_id}{suffix}"

    def _read_slice(self, index_data: Dict, slice_info: Dict, position: int, is_last: bool,
                    aesgcm: Optional[AESGCM]) -> bytes:
        legacy = self.is_legacy(index_data)
        number = position + 1

        if index_data.get('encrypted'):
            slice_path = self._slice_path(slice_info['id'], '.enc')
            if not slice_path.is_file():
                raise StorageError(f"Missing slice {number}")

            if legacy:
                with open(slice_path, 'r', encoding='utf-8') as f:
                    encrypted = json.load(f)
                nonce = base64.b64decode(encrypted['nonce'])
                ciphertext = base64.b64decode(encrypted['data'])
                aad = b""
            else:
                blob = slice_path.read_bytes()
                if hashlib.sha256(blob).hexdigest() != slice_info.get('cipher_hash'):
                    raise StorageError(f"Slice {number} is corrupted (hash mismatch)")
                nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
                aad = _slice_aad(index_data['file_id'], position, is_last)

            try:
                data = aesgcm.decrypt(nonce, ciphertext, aad)
            except InvalidTag:
                if legacy:
                    raise StorageError(
                        f"Slice {number} could not be decrypted: wrong key or corrupted data")
                raise StorageError(f"Slice {number} failed authentication (tampered, reordered or truncated)")
        else:
            suffix = '' if legacy else '.bin'
            slice_path = self._slice_path(slice_info['id'], suffix)
            if not slice_path.is_file():
                raise StorageError(f"Missing slice {number}")
            data = slice_path.read_bytes()

        if len(data) != slice_info['size']:
            raise StorageError(f"Slice {number} has an unexpected size")
        if 'hash' in slice_info and hashlib.sha256(data).hexdigest() != slice_info['hash']:
            raise StorageError(f"Hash mismatch for slice {number}")
        return data

    def restore_file(self, file_id: str, username: str, output_path: str,
                     key: Optional[bytes] = None, overwrite: bool = False,
                     progress_callback: ProgressCallback = None) -> int:
        """Rebuild a file from its slices. Returns the number of bytes written.

        The output is written to ``<output_path>.part`` and only renamed once every
        slice has been verified, so a failed restore never leaves a corrupt file.
        """
        index_data = self.get_index(file_id, username)
        encrypted = bool(index_data.get('encrypted'))

        if encrypted and key is None:
            raise StorageError("This file is encrypted; a decryption key is required")
        aesgcm = None
        if encrypted:
            try:
                aesgcm = AESGCM(key)
            except ValueError:
                raise StorageError("The decryption key has an invalid length")
            if not self.is_legacy(index_data):
                expected = (index_data.get('encryption') or {}).get('key_check', '')
                if not hmac.compare_digest(key_check_value(key), expected):
                    raise StorageError("Wrong decryption key for this file")

        slices = sorted(index_data['slices'], key=lambda s: s['index'])
        if [s['index'] for s in slices] != list(range(len(slices))):
            raise StorageError("The file index is damaged (slice numbering is not contiguous)")
        if index_data.get('total_slices', len(slices)) != len(slices):
            raise StorageError("The file index is damaged (slice count mismatch)")

        output = Path(output_path)
        if output.is_dir():
            raise StorageError(f"{output} is a directory")
        if output.exists() and not overwrite:
            raise StorageError(f"{output} already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        part_path = output.with_name(output.name + ".part")

        whole_hash = hashlib.sha256()
        bytes_written = 0
        total = len(slices)
        try:
            with open(part_path, 'wb') as out_file:
                for position, slice_info in enumerate(slices):
                    data = self._read_slice(index_data, slice_info, position,
                                            position == total - 1, aesgcm)
                    whole_hash.update(data)
                    out_file.write(data)
                    bytes_written += len(data)
                    if progress_callback:
                        progress_callback(position + 1, total)

            if bytes_written != index_data['file_info']['size']:
                raise StorageError("Restored file size does not match the index")
            expected_hash = index_data['file_info'].get('hash')
            if expected_hash and whole_hash.hexdigest() != expected_hash:
                raise StorageError("Restored file hash does not match the index")

            os.replace(part_path, output)
        except BaseException:
            try:
                part_path.unlink()
            except OSError:
                pass
            raise

        return bytes_written
