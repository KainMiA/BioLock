"""
User Authentication Manager
"""

import os
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from pathlib import Path
import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import streamlit as st

class UserManager:
    """User manager with password reset capability"""
    
    def __init__(self, data_dir: str = "users"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize session state
        if 'users' not in st.session_state:
            st.session_state.users = self._load_users()
        
        if 'current_user' not in st.session_state:
            st.session_state.current_user = None
        
        if 'user_key' not in st.session_state:
            st.session_state.user_key = None
        
        # Reset codes storage
        if 'reset_codes' not in st.session_state:
            st.session_state.reset_codes = {}
    
    def _load_users(self) -> Dict:
        """Load all users from disk"""
        users = {}
        for user_file in self.data_dir.glob("*.json"):
            try:
                with open(user_file, 'r') as f:
                    user_data = json.load(f)
                    users[user_data['username']] = user_data
            except:
                continue
        return users
    
    def _save_user(self, username: str, user_data: Dict):
        """Save user data to disk"""
        user_file = self.data_dir / f"{username}.json"
        with open(user_file, 'w') as f:
            json.dump(user_data, f, indent=2)
        
        # Update session state
        st.session_state.users[username] = user_data
    
    def get_all_users(self) -> Dict:
        """Get all users"""
        return st.session_state.users
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password"""
        try:
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
        except:
            return False
    
    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive encryption key from password"""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def create_user(self, username: str, password: str, email: str, full_name: str) -> bool:
        """Create new user"""
        if username in st.session_state.users:
            return False
        
        # Create user data
        key, salt = self.derive_key(password)
        
        user_data = {
            'username': username,
            'email': email,
            'full_name': full_name,
            'password_hash': self.hash_password(password),
            'key_salt': base64.b64encode(salt).decode(),
            'derived_key': base64.b64encode(key).decode(),
            'created': datetime.now().isoformat(),
            'last_login': None
        }
        
        # Save to disk
        self._save_user(username, user_data)
        
        return True
    
    def find_user_by_email(self, email: str) -> Optional[str]:
        """Find username by email"""
        for username, user_data in st.session_state.users.items():
            if user_data.get('email') == email:
                return username
        return None
    
    def generate_reset_code(self, email: str) -> Optional[str]:
        """Generate password reset code"""
        username = self.find_user_by_email(email)
        if not username:
            return None
        
        # Generate 6-digit code
        import random
        code = ''.join(str(random.randint(0, 9)) for _ in range(6))
        
        # Store with expiration (10 minutes)
        st.session_state.reset_codes[username] = {
            'code': code,
            'expires': (datetime.now() + timedelta(minutes=10)).isoformat()
        }
        
        return code
    
    def verify_reset_code(self, username: str, code: str) -> bool:
        """Verify reset code"""
        if username not in st.session_state.reset_codes:
            return False
        
        reset_data = st.session_state.reset_codes[username]
        
        # Check expiration
        expires = datetime.fromisoformat(reset_data['expires'])
        if datetime.now() > expires:
            del st.session_state.reset_codes[username]
            return False
        
        # Verify code
        if reset_data['code'] == code:
            return True
        
        return False
    
    def reset_password(self, username: str, code: str, new_password: str) -> bool:
        """Reset password using verification code"""
        if not self.verify_reset_code(username, code):
            return False
        
        if username not in st.session_state.users:
            return False
        
        user_data = st.session_state.users[username]
        
        # Update password and key
        user_data['password_hash'] = self.hash_password(new_password)
        
        key, salt = self.derive_key(new_password)
        user_data['key_salt'] = base64.b64encode(salt).decode()
        user_data['derived_key'] = base64.b64encode(key).decode()
        
        user_data['password_reset_at'] = datetime.now().isoformat()
        
        # Save
        self._save_user(username, user_data)
        
        # Remove used reset code
        if username in st.session_state.reset_codes:
            del st.session_state.reset_codes[username]
        
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user"""
        if username not in st.session_state.users:
            return False
        
        user_data = st.session_state.users[username]
        
        # Verify password
        if not self.verify_password(password, user_data['password_hash']):
            return False
        
        # Update last login
        user_data['last_login'] = datetime.now().isoformat()
        self._save_user(username, user_data)
        
        # Set session state
        st.session_state.current_user = {
            'username': username,
            'email': user_data['email'],
            'full_name': user_data['full_name']
        }
        
        # Set derived key
        st.session_state.user_key = user_data['derived_key']
        
        return True
    
    def get_current_user_key(self) -> Optional[str]:
        """Get current user's derived key"""
        return st.session_state.user_key
    
    def logout(self):
        """Logout user"""
        st.session_state.current_user = None
        st.session_state.user_key = None
        st.rerun()
    
    def update_user_profile(self, username: str, profile_data: Dict) -> bool:
        """Update user profile"""
        if username not in st.session_state.users:
            return False
        
        user_data = st.session_state.users[username]
        
        # Update fields
        for key, value in profile_data.items():
            if key in ['email', 'full_name']:
                user_data[key] = value
        
        user_data['updated_at'] = datetime.now().isoformat()
        
        # Save
        self._save_user(username, user_data)
        
        # Update session if current user
        if st.session_state.current_user and st.session_state.current_user['username'] == username:
            for key, value in profile_data.items():
                if key in st.session_state.current_user:
                    st.session_state.current_user[key] = value
        
        return True
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """Change password"""
        if username not in st.session_state.users:
            return False
        
        user_data = st.session_state.users[username]
        
        # If current_password is empty, allow reset
        if current_password and not self.verify_password(current_password, user_data['password_hash']):
            return False
        
        # Update password and key
        user_data['password_hash'] = self.hash_password(new_password)
        
        key, salt = self.derive_key(new_password)
        user_data['key_salt'] = base64.b64encode(salt).decode()
        user_data['derived_key'] = base64.b64encode(key).decode()
        
        user_data['password_changed_at'] = datetime.now().isoformat()
        
        # Save
        self._save_user(username, user_data)
        
        # Update session key if current user
        if st.session_state.current_user and st.session_state.current_user['username'] == username:
            st.session_state.user_key = user_data['derived_key']
        
        return True

class SecureKeyManager:
    """Key management utilities"""
    
    @staticmethod
    def generate_encryption_key() -> str:
        """Generate AES-256 encryption key"""
        key = secrets.token_bytes(32)
        return base64.b64encode(key).decode()