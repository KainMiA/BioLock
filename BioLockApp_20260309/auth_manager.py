"""
User Authentication Manager

Key hierarchy
-------------
Every user owns a random 256-bit *master key*. It is the key used when a file
is stored with "Use my password". The master key is never written to disk in
plain form; it is stored wrapped with AES-256-GCM:

* by a key derived from the login password (PBKDF2-HMAC-SHA256), and
* by a random recovery key that is shown to the user once.

Changing the password only re-wraps the master key, so previously stored
files stay readable. A password reset that supplies the recovery key keeps the
master key too; a reset without it has to create a new master key.

This module has no Streamlit dependency so it can be tested on its own.
"""

import json
import base64
import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import (
    PASSWORD_RULES,
    atomic_write_json,
    decode_raw_key,
    is_password_strong,
    validate_email,
    validate_username,
)

PBKDF2_ITERATIONS = 600_000          # OWASP recommendation for PBKDF2-HMAC-SHA256
LEGACY_PBKDF2_ITERATIONS = 100_000   # used by accounts created before key wrapping
RESET_CODE_TTL = timedelta(minutes=10)
RESET_CODE_MAX_ATTEMPTS = 5


class AuthError(Exception):
    """Raised with a user-facing message when an account operation fails"""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode('ascii'), validate=True)


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit key from a password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode('utf-8'))


def _wrap_key(master_key: bytes, wrapping_key: bytes, label: bytes) -> Dict:
    nonce = secrets.token_bytes(12)
    return {
        'nonce': _b64e(nonce),
        'data': _b64e(AESGCM(wrapping_key).encrypt(nonce, master_key, label))
    }


def _unwrap_key(wrapped: Dict, wrapping_key: bytes, label: bytes) -> bytes:
    """Raises InvalidTag when the wrapping key is wrong"""
    return AESGCM(wrapping_key).decrypt(_b64d(wrapped['nonce']), _b64d(wrapped['data']), label)


def _label(username: str, purpose: str) -> bytes:
    return f"BioLock master key|{purpose}|{username}".encode('utf-8')


class UserManager:
    """User manager with key wrapping and password reset capability.

    One instance is shared by all Streamlit sessions, so every method reads
    from disk and writes atomically under a lock.
    """

    def __init__(self, data_dir: str = "users"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._reset_codes: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _user_file(self, username: str) -> Path:
        if not validate_username(username):
            raise AuthError("Invalid username")
        return self.data_dir / f"{username}.json"

    def _load_user(self, username: str) -> Optional[Dict]:
        if not validate_username(username):
            return None
        path = self.data_dir / f"{username}.json"
        if not path.is_file():
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        # On case-insensitive file systems "alice.json" also opens "Alice.json"
        return data if data.get('username') == username else None

    def _all_users(self) -> List[Dict]:
        users = []
        for user_file in self.data_dir.glob("*.json"):
            try:
                with open(user_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict) and 'username' in data:
                    users.append(data)
            except (OSError, ValueError):
                continue
        return users

    def _save_user(self, user_data: Dict):
        atomic_write_json(self._user_file(user_data['username']), user_data)

    @staticmethod
    def _public_profile(user_data: Dict) -> Dict:
        return {
            'username': user_data['username'],
            'email': user_data.get('email', ''),
            'full_name': user_data.get('full_name', '')
        }

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('ascii')

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('ascii'))
        except (ValueError, TypeError):
            return False

    def _set_password(self, user_data: Dict, master_key: bytes, password: str):
        """Store a new password hash and re-wrap the master key with it"""
        salt = secrets.token_bytes(16)
        kek = derive_key(password, salt, PBKDF2_ITERATIONS)
        user_data['password_hash'] = self.hash_password(password)
        user_data['key_salt'] = _b64e(salt)
        user_data['kdf_iterations'] = PBKDF2_ITERATIONS
        user_data['wrapped_master_key'] = _wrap_key(
            master_key, kek, _label(user_data['username'], 'password'))

    @staticmethod
    def _set_recovery_key(user_data: Dict, master_key: bytes) -> str:
        recovery_key = secrets.token_bytes(32)
        user_data['recovery_wrapped_master_key'] = _wrap_key(
            master_key, recovery_key, _label(user_data['username'], 'recovery'))
        return _b64e(recovery_key)

    def _unlock_master_key(self, user_data: Dict, password: str) -> bytes:
        """Return the user's master key. The password must already be verified.

        Accounts created by older BioLock versions stored the PBKDF2-derived key
        itself on disk. That key keeps being the master key (so existing files
        stay readable), but it is wrapped and the plain copy is removed.
        """
        if 'wrapped_master_key' in user_data:
            kek = derive_key(password, _b64d(user_data['key_salt']),
                             int(user_data.get('kdf_iterations', PBKDF2_ITERATIONS)))
            try:
                return _unwrap_key(user_data['wrapped_master_key'], kek,
                                   _label(user_data['username'], 'password'))
            except InvalidTag:
                raise AuthError("Unable to unlock your encryption key (account data is damaged)")

        if user_data.get('derived_key'):
            master_key = _b64d(user_data['derived_key'])
        else:
            master_key = derive_key(password, _b64d(user_data['key_salt']), LEGACY_PBKDF2_ITERATIONS)

        self._set_password(user_data, master_key, password)
        user_data.pop('derived_key', None)
        user_data['migrated_at'] = datetime.now().isoformat()
        return master_key

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def find_user_by_email(self, email: str) -> Optional[str]:
        """Find username by email (case-insensitive)"""
        email = (email or '').strip().lower()
        for user_data in self._all_users():
            if user_data.get('email', '').strip().lower() == email:
                return user_data['username']
        return None

    def _username_taken(self, username: str) -> bool:
        lowered = username.lower()
        return any(u['username'].lower() == lowered for u in self._all_users())

    def create_user(self, username: str, password: str, email: str, full_name: str) -> str:
        """Create a new user and return the recovery key (shown to the user once)"""
        username = (username or '').strip()
        email = (email or '').strip()
        full_name = (full_name or '').strip()

        if not validate_username(username):
            raise AuthError("Username must be 3-32 characters: letters, numbers, '.', '_' or '-'")
        if not validate_email(email):
            raise AuthError("Please enter a valid email address")
        if not is_password_strong(password):
            raise AuthError(PASSWORD_RULES)

        user_data = {
            'username': username,
            'email': email,
            'full_name': full_name,
            'created': datetime.now().isoformat(),
            'last_login': None
        }
        master_key = secrets.token_bytes(32)
        # Key derivation is slow, so do it before taking the lock
        self._set_password(user_data, master_key, password)
        recovery_key = self._set_recovery_key(user_data, master_key)

        with self._lock:
            if self._username_taken(username):
                raise AuthError("Username already exists")
            if self.find_user_by_email(email):
                raise AuthError("An account with this email already exists")
            self._save_user(user_data)

        return recovery_key

    def authenticate_user(self, username: str, password: str) -> Optional[Tuple[Dict, bytes]]:
        """Return (profile, master_key) on success, None on bad credentials"""
        username = (username or '').strip()
        user_data = self._load_user(username)
        if not user_data or not self.verify_password(password, user_data.get('password_hash', '')):
            return None

        with self._lock:
            master_key = self._unlock_master_key(user_data, password)
            user_data['last_login'] = datetime.now().isoformat()
            self._save_user(user_data)

        return self._public_profile(user_data), master_key

    def get_profile(self, username: str) -> Optional[Dict]:
        user_data = self._load_user(username)
        return self._public_profile(user_data) if user_data else None

    def has_recovery_key(self, username: str) -> bool:
        user_data = self._load_user(username)
        return bool(user_data and user_data.get('recovery_wrapped_master_key'))

    def update_user_profile(self, username: str, full_name: str, email: str) -> Dict:
        """Update name/email and return the new public profile"""
        email = (email or '').strip()
        full_name = (full_name or '').strip()
        if not validate_email(email):
            raise AuthError("Invalid email address")

        with self._lock:
            user_data = self._load_user(username)
            if not user_data:
                raise AuthError("User not found")
            owner = self.find_user_by_email(email)
            if owner and owner != username:
                raise AuthError("Another account already uses this email")

            user_data['email'] = email
            user_data['full_name'] = full_name
            user_data['updated_at'] = datetime.now().isoformat()
            self._save_user(user_data)

        return self._public_profile(user_data)

    def change_password(self, username: str, current_password: str, new_password: str):
        """Change password; the master key (and therefore every file) is kept"""
        if not current_password:
            raise AuthError("Please enter your current password")
        if not is_password_strong(new_password):
            raise AuthError(PASSWORD_RULES)

        with self._lock:
            user_data = self._load_user(username)
            if not user_data:
                raise AuthError("User not found")
            if not self.verify_password(current_password, user_data['password_hash']):
                raise AuthError("Incorrect current password")

            master_key = self._unlock_master_key(user_data, current_password)
            self._set_password(user_data, master_key, new_password)
            user_data['password_changed_at'] = datetime.now().isoformat()
            self._save_user(user_data)

    def regenerate_recovery_key(self, username: str, password: str) -> str:
        """Create a new recovery key (the old one stops working)"""
        with self._lock:
            user_data = self._load_user(username)
            if not user_data:
                raise AuthError("User not found")
            if not self.verify_password(password, user_data['password_hash']):
                raise AuthError("Incorrect password")

            master_key = self._unlock_master_key(user_data, password)
            recovery_key = self._set_recovery_key(user_data, master_key)
            self._save_user(user_data)

        return recovery_key

    # ------------------------------------------------------------------
    # Password reset
    # ------------------------------------------------------------------

    def request_password_reset(self, email: str) -> Optional[Tuple[str, str]]:
        """Create a 6-digit reset code. Returns (username, code) or None"""
        username = self.find_user_by_email(email)
        if not username:
            return None

        code = f"{secrets.randbelow(1_000_000):06d}"
        with self._lock:
            self._reset_codes[username] = {
                'code_hash': hashlib.sha256(code.encode()).hexdigest(),
                'expires': datetime.now() + RESET_CODE_TTL,
                'attempts': 0
            }
        return username, code

    def _check_reset_code(self, username: str, code: str) -> bool:
        entry = self._reset_codes.get(username)
        if not entry:
            return False
        if datetime.now() > entry['expires'] or entry['attempts'] >= RESET_CODE_MAX_ATTEMPTS:
            del self._reset_codes[username]
            return False

        candidate = hashlib.sha256((code or '').strip().encode()).hexdigest()
        if hmac.compare_digest(candidate, entry['code_hash']):
            return True

        entry['attempts'] += 1
        return False

    def reset_password(self, username: str, code: str, new_password: str,
                       recovery_key: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Reset the password with a verification code.

        Returns (keys_preserved, new_recovery_key). Without a valid recovery key a
        new master key is created, and files encrypted with the old password key
        can no longer be restored with the password.
        """
        if not is_password_strong(new_password):
            raise AuthError(PASSWORD_RULES)

        with self._lock:
            if not self._check_reset_code(username, code):
                raise AuthError("Invalid or expired verification code")

            user_data = self._load_user(username)
            if not user_data:
                raise AuthError("User not found")

            new_recovery_key = None
            if recovery_key and recovery_key.strip():
                raw_recovery = decode_raw_key(recovery_key)
                if raw_recovery is None:
                    raise AuthError("The recovery key is not in a valid format")
                wrapped = user_data.get('recovery_wrapped_master_key')
                if not wrapped:
                    raise AuthError("This account has no recovery key")
                try:
                    master_key = _unwrap_key(wrapped, raw_recovery, _label(username, 'recovery'))
                except InvalidTag:
                    raise AuthError("The recovery key is incorrect")
                keys_preserved = True
            else:
                master_key = secrets.token_bytes(32)
                new_recovery_key = self._set_recovery_key(user_data, master_key)
                keys_preserved = False
                user_data.pop('derived_key', None)

            self._set_password(user_data, master_key, new_password)
            user_data['password_reset_at'] = datetime.now().isoformat()
            self._save_user(user_data)
            self._reset_codes.pop(username, None)

        return keys_preserved, new_recovery_key


class SecureKeyManager:
    """Key management utilities"""

    @staticmethod
    def generate_encryption_key() -> str:
        """Generate AES-256 encryption key"""
        return _b64e(secrets.token_bytes(32))
