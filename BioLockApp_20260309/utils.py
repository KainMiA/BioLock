"""
Utility Functions
"""

import os
import re
import json
import base64
import binascii
import smtplib
import tempfile
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Optional

USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# bcrypt only uses the first 72 bytes of a password (and bcrypt>=5 rejects longer ones)
MAX_PASSWORD_BYTES = 72


def format_file_size(size_bytes: int) -> str:
    """Format file size to human readable format"""
    if size_bytes <= 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    size = float(size_bytes)

    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1

    if i == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[i]}"


def validate_email(email: str) -> bool:
    """Validate email format"""
    return bool(EMAIL_PATTERN.match(email or ''))


def validate_username(username: str) -> bool:
    """Usernames are used as file names, so only allow a safe character set"""
    return bool(USERNAME_PATTERN.match(username or ''))


def is_password_strong(password: str) -> bool:
    """Check password strength"""
    if not password or len(password) < 8:
        return False
    if len(password.encode('utf-8')) > MAX_PASSWORD_BYTES:
        return False

    # Check for mixed case and numbers
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)

    return has_lower and has_upper and has_digit


PASSWORD_RULES = (
    "Password must be 8-72 characters long and contain uppercase letters, "
    "lowercase letters and numbers"
)


def decode_raw_key(text: Optional[str], length: int = 32) -> Optional[bytes]:
    """Decode a base64 key (as generated on the Keys page); None if it is not one"""
    if not text:
        return None
    cleaned = ''.join(text.split())
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == length else None


def ensure_directory(path: str) -> str:
    """Ensure directory exists"""
    os.makedirs(path, exist_ok=True)
    return path


def atomic_write_json(path: Path, data: Any):
    """Write JSON so that readers never see a half-written file"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
        raise


# ----------------------------------------------------------------------------
# Optional email delivery (used for password reset codes)
# ----------------------------------------------------------------------------

def smtp_configured() -> bool:
    """True when the BIOLOCK_SMTP_* environment variables are set"""
    return bool(os.environ.get('BIOLOCK_SMTP_HOST') and os.environ.get('BIOLOCK_SMTP_FROM'))


def send_email(to_address: str, subject: str, body: str):
    """Send an email using the SMTP server configured in the environment.

    Raises on failure so the caller can report it.
    """
    host = os.environ['BIOLOCK_SMTP_HOST']
    port = int(os.environ.get('BIOLOCK_SMTP_PORT', '587'))
    user = os.environ.get('BIOLOCK_SMTP_USER')
    password = os.environ.get('BIOLOCK_SMTP_PASSWORD')
    sender = os.environ['BIOLOCK_SMTP_FROM']

    message = EmailMessage()
    message['From'] = sender
    message['To'] = to_address
    message['Subject'] = subject
    message.set_content(body)

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30) as server:
            if user:
                server.login(user, password or '')
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.starttls()
            if user:
                server.login(user, password or '')
            server.send_message(message)
