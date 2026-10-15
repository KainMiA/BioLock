"""
BioLock - Secure File Storage System
"""

import os
import base64
import sys
import json
from pathlib import Path
from datetime import datetime

import streamlit as st

# Add project root to Python path
APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))

try:
    from dotenv import load_dotenv
    load_dotenv(APP_DIR / ".env")
except ImportError:
    pass

# Import custom modules
from auth_manager import AuthError, SecureKeyManager, UserManager
from file_storage import (
    MAX_SLICE_MB,
    MIN_PASSPHRASE_LENGTH,
    FileStorageManager,
    StorageError,
    resolve_custom_key,
)
from utils import (
    PASSWORD_RULES,
    format_file_size,
    is_password_strong,
    send_email,
    smtp_configured,
    validate_email,
)

# All data (users/, indexes/, storage/) lives here
DATA_DIR = Path(os.environ.get("BIOLOCK_DATA_DIR", str(APP_DIR))).resolve()
# Restored files up to this size can also be downloaded through the browser
DOWNLOAD_LIMIT = 200 * 1024 * 1024
SLICE_OPTIONS = [s for s in (1, 5, 10, 20, 50, 100, 200, 500) if s <= MAX_SLICE_MB]

# Page configuration
st.set_page_config(
    page_title="BioLock",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Badge colours are semi-transparent so they work in both light and dark themes
st.markdown("""
<style>
    .biolock-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 500;
    }
    .biolock-badge-encrypted {
        background: rgba(30, 136, 229, 0.18);
        color: #1e88e5;
    }
    .biolock-badge-plain {
        background: rgba(76, 175, 80, 0.18);
        color: #43a047;
    }
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #4f46e5, #7c3aed) !important;
    }
</style>
""", unsafe_allow_html=True)


# Managers are shared by every browser session; per-session data lives in st.session_state
@st.cache_resource
def init_user_manager() -> UserManager:
    return UserManager(str(DATA_DIR / "users"))


@st.cache_resource
def init_storage_manager() -> FileStorageManager:
    return FileStorageManager(str(DATA_DIR))


user_manager = init_user_manager()
storage_manager = init_storage_manager()

# ============================================================================
# Helper Functions
# ============================================================================

SESSION_DEFAULTS = {
    'current_user': None,       # public profile dict
    'master_key': None,         # bytes, the "Use my password" key
    'current_page': 'dashboard',
    'selected_file_id': None,
    'last_restore': None,
    'reset_username': None,
    'reset_email': None,
    'new_key': None,
    'shown_recovery_key': None,
    'flash': None,
}


def init_session_state():
    for name, value in SESSION_DEFAULTS.items():
        if name not in st.session_state:
            st.session_state[name] = value


def flash(kind: str, message: str):
    """Show a message after the next rerun"""
    st.session_state.flash = (kind, message)


def render_flash():
    if st.session_state.flash:
        kind, message = st.session_state.flash
        getattr(st, kind)(message)
        st.session_state.flash = None


def badge(encrypted: bool) -> str:
    if encrypted:
        return '<span class="biolock-badge biolock-badge-encrypted">Encrypted</span>'
    return '<span class="biolock-badge biolock-badge-plain">Plain</span>'


def logout():
    for name in list(st.session_state.keys()):
        del st.session_state[name]
    init_session_state()
    st.rerun()


def render_recovery_key(recovery_key: str, username: str):
    """Show a recovery key once, with a way to save it"""
    st.warning(
        "**Save your recovery key now.** It is shown only once. If you forget your "
        "password, it is the only way to keep access to files encrypted with "
        "\"Use my password\".")
    st.code(recovery_key, language=None)
    st.download_button(
        "Save Recovery Key",
        data=json.dumps({
            "type": "BioLock recovery key",
            "user": username,
            "recovery_key": recovery_key,
            "generated": datetime.now().isoformat()
        }, indent=2),
        file_name=f"biolock_recovery_{username}.json",
        mime="application/json",
    )
    if st.button("I have saved my recovery key", key="dismiss_recovery_key"):
        st.session_state.shown_recovery_key = None
        st.rerun()


def render_sidebar():
    """Render sidebar"""
    with st.sidebar:
        user = st.session_state.current_user

        st.markdown(f"### {user['username']}")
        st.caption(user.get('email', ''))
        st.divider()

        # Navigation
        pages = [
            ("Home", "dashboard"),
            ("Store Files", "storage"),
            ("Restore Files", "restore"),
            ("My Files", "my_files"),
            ("Keys", "keys"),
            ("Settings", "settings"),
            ("Help", "help")
        ]

        for label, page in pages:
            is_active = st.session_state.current_page == page
            if st.button(label, type="primary" if is_active else "secondary",
                         width="stretch", key=f"nav_{page}"):
                st.session_state.current_page = page
                st.rerun()

        st.divider()

        if st.button("Logout", type="secondary", width="stretch"):
            logout()


# ============================================================================
# Login / Register / Reset
# ============================================================================

def render_login_page():
    """Render login page"""
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("""
        <div style='text-align: center; margin-bottom: 40px;'>
            <h1>BioLock</h1>
            <p>Secure Biomedical File Storage with End-to-End Encryption</p>
        </div>
        """, unsafe_allow_html=True)

        render_flash()

        tab1, tab2, tab3 = st.tabs(["Login", "Register", "Reset Password"])

        with tab1:
            render_login_form()
        with tab2:
            render_register_form()
        with tab3:
            render_reset_form()


def render_login_form():
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")

        if st.form_submit_button("Login", type="primary", width="stretch"):
            if not username or not password:
                st.error("Please fill all fields")
                return
            try:
                with st.spinner("Signing in..."):
                    result = user_manager.authenticate_user(username, password)
            except AuthError as e:
                st.error(str(e))
                return

            if result is None:
                st.error("Invalid username or password")
                return

            profile, master_key = result
            st.session_state.current_user = profile
            st.session_state.master_key = master_key
            st.session_state.current_page = "dashboard"
            st.rerun()


def render_register_form():
    shown = st.session_state.shown_recovery_key
    if shown and shown.get('context') == 'register':
        st.success("Account created successfully! You can now log in.")
        render_recovery_key(shown['key'], shown['username'])
        return

    with st.form("register_form"):
        col1, col2 = st.columns(2)
        with col1:
            full_name = st.text_input("Full Name", placeholder="Your full name")
            username = st.text_input("Username", placeholder="Choose username",
                                     help="3-32 characters: letters, numbers, '.', '_' or '-'")
        with col2:
            email = st.text_input("Email", placeholder="your@email.com")

        password = st.text_input("Password", type="password", placeholder="Create strong password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")
        st.caption(PASSWORD_RULES)

        if st.form_submit_button("Create Account", type="primary", width="stretch"):
            if not all([full_name, email, username, password, confirm_password]):
                st.error("Please fill all required fields")
            elif password != confirm_password:
                st.error("Passwords do not match")
            else:
                try:
                    with st.spinner("Creating account..."):
                        recovery_key = user_manager.create_user(username, password, email, full_name)
                except AuthError as e:
                    st.error(str(e))
                else:
                    st.session_state.shown_recovery_key = {
                        'context': 'register',
                        'username': username.strip(),
                        'key': recovery_key
                    }
                    st.rerun()


def render_reset_form():
    shown = st.session_state.shown_recovery_key
    if shown and shown.get('context') == 'reset':
        st.success("Password reset successfully! Please log in with your new password.")
        render_recovery_key(shown['key'], shown['username'])
        return

    with st.form("reset_password_form"):
        email = st.text_input("Email", placeholder="Enter your registered email")

        if st.form_submit_button("Send Verification Code", type="primary", width="stretch"):
            if not validate_email(email):
                st.error("Please enter a valid email")
            else:
                request = user_manager.request_password_reset(email)
                if smtp_configured():
                    if request:
                        username, code = request
                        try:
                            send_email(
                                email.strip(),
                                "BioLock password reset code",
                                f"Your BioLock verification code is {code}. "
                                f"It expires in 10 minutes.")
                        except Exception as e:
                            st.error(f"Failed to send email: {e}")
                            request = None
                    if request:
                        st.session_state.reset_username = request[0]
                        st.session_state.reset_email = email.strip()
                    # Same message either way so the form does not reveal who has an account
                    st.success(f"If an account uses {email}, a verification code has been sent to it.")
                elif request:
                    username, code = request
                    st.session_state.reset_username = username
                    st.session_state.reset_email = email.strip()
                    st.warning(
                        "Demo mode: no email server is configured (see README, BIOLOCK_SMTP_*), "
                        f"so the code is shown here: **{code}**. Anyone who knows an "
                        "account's email can reset its password in this mode.")
                else:
                    st.error("No account found with this email")

    if not st.session_state.reset_username:
        return

    st.caption(f"Resetting the password for {st.session_state.reset_email}")
    with st.form("verify_reset_form"):
        verification_code = st.text_input("Verification Code", placeholder="Enter 6-digit code")
        new_password = st.text_input("New Password", type="password", placeholder="New password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm new password")
        recovery_key = st.text_input(
            "Recovery Key (optional)", type="password",
            placeholder="Paste the recovery key you saved when registering",
            help="Without it, files encrypted with \"Use my password\" cannot be "
                 "restored with your new password.")

        if st.form_submit_button("Reset Password", type="primary", width="stretch"):
            if not verification_code:
                st.error("Please enter the verification code")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            elif not is_password_strong(new_password):
                st.error(PASSWORD_RULES)
            else:
                username = st.session_state.reset_username
                try:
                    with st.spinner("Resetting password..."):
                        preserved, new_recovery_key = user_manager.reset_password(
                            username, verification_code, new_password, recovery_key)
                except AuthError as e:
                    st.error(str(e))
                    return

                st.session_state.reset_username = None
                st.session_state.reset_email = None
                if preserved:
                    flash("success", "Password reset successfully! Your encryption key was "
                                     "kept, so all your files remain accessible.")
                else:
                    flash("warning", "Password reset. No recovery key was given, so a new "
                                     "encryption key was created: files encrypted with your "
                                     "old password key can no longer be restored with "
                                     "\"Use my password\".")
                    st.session_state.shown_recovery_key = {
                        'context': 'reset',
                        'username': username,
                        'key': new_recovery_key
                    }
                st.rerun()


# ============================================================================
# Pages
# ============================================================================

def render_dashboard():
    """Render dashboard"""
    user = st.session_state.current_user

    st.title(f"Welcome back, {user.get('full_name') or user['username']}")

    user_files = storage_manager.get_user_files(user['username'])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Your Files", len(user_files))
    with col2:
        st.metric("Your Storage", format_file_size(sum(f['size'] for f in user_files)))
    with col3:
        st.metric("Encrypted", sum(1 for f in user_files if f['encrypted']))

    if not user_manager.has_recovery_key(user['username']):
        st.warning("Your account has no recovery key yet. Create one on the **Keys** page "
                   "so a forgotten password does not lock you out of your encrypted files.")

    st.divider()
    st.subheader("Recent Files")

    if user_files:
        # get_user_files is sorted newest first
        for file in user_files[:5]:
            col1, col2, col3 = st.columns([3, 2, 1])
            with col1:
                st.write(f"**{file['name']}**")
                st.caption(f"Stored: {file['created'][:10]}")
            with col2:
                st.write(format_file_size(file['size']))
            with col3:
                st.markdown(badge(file['encrypted']), unsafe_allow_html=True)
    else:
        st.info("No files yet. Store your first file to get started!")


def render_storage_page():
    """Render file storage page"""
    st.title("Store File")

    upload_mode = st.radio(
        "Upload Mode",
        ["Standard Upload (Up to 200MB)", "Large File Upload (Any Size)"],
        horizontal=True,
        help="Large file mode reads the file straight from disk in slices, so it is "
             "never loaded into memory as a whole"
    )
    large_mode = upload_mode.startswith("Large")

    uploaded_file = None
    file_path = None
    filename = None
    file_size = 0

    if not large_mode:
        uploaded_file = st.file_uploader(
            "Select file to store",
            type=None,
            help="Choose any file to encrypt and store securely"
        )
        if uploaded_file is not None:
            filename = uploaded_file.name
            file_size = uploaded_file.size
    else:
        st.info("Large File Mode: enter the path of a file on the computer running BioLock. "
                "The file is processed in slices and never loaded into memory as a whole.")

        raw_path = st.text_input(
            "File Path",
            placeholder="C:/path/to/your/large/file.dat or /home/user/largefile.dat",
            help="Enter the full path to the file (surrounding quotes are ignored)"
        )
        candidate = raw_path.strip().strip('"').strip("'")
        if candidate:
            candidate = os.path.expanduser(candidate)
            if os.path.isfile(candidate):
                file_path = candidate
                filename = os.path.basename(candidate)
                file_size = os.path.getsize(candidate)
            elif os.path.isdir(candidate):
                st.error("That path is a directory; please enter a file path")
            else:
                st.error("File not found")

    if not filename:
        return

    st.success(f"**File selected:** {filename} ({format_file_size(file_size)})")

    with st.expander("Storage Settings", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            # Larger files get larger slices by default
            if file_size > 1024 * 1024 * 1024:
                default_slice = 50
            elif file_size > 100 * 1024 * 1024:
                default_slice = 20
            else:
                default_slice = 10

            slice_size = st.select_slider(
                "Slice Size",
                options=SLICE_OPTIONS,
                value=default_slice,
                format_func=lambda x: f"{x} MB"
            )

        with col2:
            encryption = st.radio("Encryption", ["Enabled", "Disabled"], horizontal=True)

        custom_key_text = None
        key_source = None
        if encryption == "Enabled":
            key_source = st.radio("Encryption Key", ["Use my password", "Custom key"], horizontal=True)

            if key_source == "Use my password":
                st.info("Using the encryption key protected by your password")
            else:
                custom_key_text = st.text_input(
                    "Custom encryption key",
                    type="password",
                    placeholder="Paste a generated key or type a passphrase"
                )
                st.caption(
                    "Use a key from the **Keys** page, or a passphrase of at least "
                    f"{MIN_PASSPHRASE_LENGTH} characters. You will need exactly the same "
                    "key to restore the file - it is not stored anywhere.")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if not st.button("Store File", type="primary", width="stretch"):
            return

    key = None
    key_info = None
    if encryption == "Enabled":
        try:
            if key_source == "Use my password":
                key = st.session_state.master_key
                key_info = {'key_source': 'password', 'key_mode': 'raw'}
                if key is None:
                    st.error("Your session key is missing; please log in again")
                    return
            else:
                key, key_info = resolve_custom_key(custom_key_text or '')
        except StorageError as e:
            st.error(str(e))
            return

    progress_bar = st.progress(0.0)
    status_text = st.empty()

    def update_progress(current, total):
        progress_bar.progress(min(current / total, 1.0) if total else 1.0)
        status_text.text(f"Processing: {format_file_size(current)} / {format_file_size(total)}")

    username = st.session_state.current_user['username']
    try:
        with st.spinner("Storing file..."):
            if large_mode:
                result = storage_manager.store_large_file(
                    file_path=file_path,
                    username=username,
                    slice_mb=slice_size,
                    key=key,
                    key_info=key_info,
                    progress_callback=update_progress
                )
            else:
                result = storage_manager.store_file(
                    file_stream=uploaded_file,
                    filename=filename,
                    username=username,
                    slice_mb=slice_size,
                    key=key,
                    key_info=key_info,
                    total_size=file_size,
                    progress_callback=update_progress
                )
    except (StorageError, OSError) as e:
        progress_bar.empty()
        status_text.empty()
        st.error(f"Failed to store file: {e}")
        return

    progress_bar.empty()
    status_text.empty()
    st.success(f"File stored successfully in {result['slices']} slice(s)"
               f"{' and encrypted' if result['encrypted'] else ''}.")
    st.info(f"File ID: {result['file_id']}")
    st.balloons()


def render_restore_page():
    """Render file restoration page"""
    st.title("Restore Files")

    user = st.session_state.current_user
    user_files = storage_manager.get_user_files(user['username'])

    if st.session_state.last_restore:
        render_last_restore()

    if not user_files:
        st.info("No files available for restoration")
        return

    st.subheader("Select File to Restore")

    selected = next((f for f in user_files if f['id'] == st.session_state.selected_file_id), None)

    for file in user_files:
        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
        with col1:
            st.write(f"**{file['name']}**")
            st.caption(f"Stored: {file['created'][:10]}")
        with col2:
            st.write(format_file_size(file['size']))
        with col3:
            st.markdown(badge(file['encrypted']), unsafe_allow_html=True)
        with col4:
            is_selected = selected is not None and selected['id'] == file['id']
            if st.button("Selected" if is_selected else "Select",
                         key=f"select_{file['id']}",
                         type="primary" if is_selected else "secondary",
                         width="stretch"):
                st.session_state.selected_file_id = file['id']
                st.session_state.last_restore = None
                st.rerun()
        st.divider()

    if selected is None:
        st.info("Select a file from the list above to restore it")
        return

    st.subheader(f"Restore: {selected['name']}")

    col1, col2 = st.columns(2)
    with col1:
        restore_dir = st.text_input(
            "Output Directory",
            value=str(DATA_DIR / "restored"),
            key=f"restore_dir_{selected['id']}",
            help="Directory on the computer running BioLock"
        )
    with col2:
        filename = st.text_input(
            "Filename",
            value=selected['name'],
            key=f"restore_name_{selected['id']}",
            help="Name for the restored file"
        )
    overwrite = st.checkbox("Overwrite if the file already exists", value=False)

    custom_key_text = None
    use_password_key = False
    if selected['encrypted']:
        st.warning("This file is encrypted")
        # Pre-select the key type the file was stored with
        default_index = 1 if selected.get('key_source') == 'custom' else 0
        key_choice = st.radio(
            "Decryption Key",
            ["Use my password", "Custom key"],
            index=default_index,
            horizontal=True,
            key=f"restore_key_choice_{selected['id']}"
        )
        if key_choice == "Use my password":
            use_password_key = True
            st.info("Using the encryption key protected by your password")
        else:
            custom_key_text = st.text_input(
                "Enter decryption key",
                type="password",
                placeholder="Paste the key or passphrase used when storing the file",
                key=f"restore_key_{selected['id']}"
            )

    col1, col2 = st.columns(2)
    with col1:
        restore_clicked = st.button("Restore File", type="primary", width="stretch")
    with col2:
        if st.button("Cancel", type="secondary", width="stretch"):
            st.session_state.selected_file_id = None
            st.rerun()

    if not restore_clicked:
        return

    errors = []
    if not restore_dir.strip():
        errors.append("Please specify output directory")
    if not filename.strip():
        errors.append("Please specify filename")
    elif os.path.basename(filename.strip()) != filename.strip() or filename.strip() in ('.', '..'):
        errors.append("The filename must not contain a path")
    if selected['encrypted'] and not use_password_key and not custom_key_text:
        errors.append("Encrypted file requires decryption key")
    if errors:
        for error in errors:
            st.error(error)
        return

    output_path = os.path.join(os.path.expanduser(restore_dir.strip()), filename.strip())
    progress_bar = st.progress(0.0)

    def update_progress(current, total):
        progress_bar.progress(min(current / total, 1.0) if total else 1.0)

    try:
        with st.spinner("Restoring file..."):
            key = None
            if selected['encrypted']:
                key = storage_manager.resolve_restore_key(
                    selected['id'], user['username'],
                    master_key=st.session_state.master_key if use_password_key else None,
                    custom_key=custom_key_text if not use_password_key else None)
            size = storage_manager.restore_file(
                file_id=selected['id'],
                username=user['username'],
                output_path=output_path,
                key=key,
                overwrite=overwrite,
                progress_callback=update_progress
            )
    except (StorageError, OSError) as e:
        progress_bar.empty()
        st.error(f"Failed to restore file: {e}")
        return

    progress_bar.empty()
    st.session_state.last_restore = {'path': os.path.abspath(output_path), 'size': size}
    st.session_state.selected_file_id = None
    st.rerun()


def render_last_restore():
    info = st.session_state.last_restore
    st.success(f"File restored to: `{info['path']}` ({format_file_size(info['size'])})")

    if info['size'] <= DOWNLOAD_LIMIT and os.path.isfile(info['path']):
        with open(info['path'], 'rb') as f:
            data = f.read()
        st.download_button(
            "Download restored file",
            data=data,
            file_name=os.path.basename(info['path']),
            mime="application/octet-stream",
        )
    if st.button("Dismiss", key="dismiss_restore"):
        st.session_state.last_restore = None
        st.rerun()
    st.divider()


def render_my_files_page():
    """Render user files page"""
    st.title("My Files")

    user = st.session_state.current_user
    user_files = storage_manager.get_user_files(user['username'])

    if not user_files:
        st.info("You haven't stored any files yet")
        if st.button("Store Your First File", type="primary"):
            st.session_state.current_page = "storage"
            st.rerun()
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Files", len(user_files))
    with col2:
        st.metric("Total Size", format_file_size(sum(f['size'] for f in user_files)))
    with col3:
        st.metric("Encrypted", sum(1 for f in user_files if f['encrypted']))

    st.divider()

    search_query = st.text_input("Search files", placeholder="Type to search...")

    filtered_files = user_files
    if search_query:
        filtered_files = [f for f in user_files if search_query.lower() in f['name'].lower()]

    if not filtered_files:
        st.info("No files match your search")
        return

    for file in filtered_files:
        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
        with col1:
            st.write(f"**{file['name']}**")
            st.caption(f"ID: {file['id'][:12]}... • Stored: {file['created'][:10]} • "
                       f"{file['slices']} slice(s)")
        with col2:
            st.write(format_file_size(file['size']))
        with col3:
            st.markdown(badge(file['encrypted']), unsafe_allow_html=True)
        with col4:
            if st.button("Restore", key=f"restore_{file['id']}", width="stretch"):
                st.session_state.selected_file_id = file['id']
                st.session_state.last_restore = None
                st.session_state.current_page = "restore"
                st.rerun()
        st.divider()


def render_keys_page():
    """Render key management page"""
    st.title("Encryption Keys")

    user = st.session_state.current_user
    tab1, tab2, tab3 = st.tabs(["Password Key", "Custom Keys", "Recovery Key"])

    with tab1:
        st.subheader("Password Key")
        st.info("Files stored with \"Use my password\" are encrypted with this key. It is kept "
                "on disk only in encrypted form, unlocked by your password, so changing "
                "your password does not affect your files.")

        master_key = st.session_state.master_key
        if master_key is None:
            st.warning("Unable to retrieve key; please log in again")
        elif st.toggle("Show key"):
            st.code(base64.b64encode(master_key).decode(), language=None)
            st.caption("Anyone with this key can decrypt your password-encrypted files. "
                       "It can be used as a custom key when restoring.")

    with tab2:
        st.subheader("Custom Keys")

        if st.button("Generate New Key", type="primary", width="stretch"):
            st.session_state.new_key = SecureKeyManager.generate_encryption_key()

        if st.session_state.new_key:
            st.code(st.session_state.new_key, language=None)
            st.download_button(
                "Save Key File",
                data=json.dumps({
                    "key": st.session_state.new_key,
                    "generated": datetime.now().isoformat(),
                    "user": user['username']
                }, indent=2),
                file_name=f"key_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                width="stretch"
            )
            st.warning("Save this key securely! Lost keys cannot recover encrypted files.")

    with tab3:
        st.subheader("Recovery Key")
        shown = st.session_state.shown_recovery_key
        if shown and shown.get('context') == 'keys':
            render_recovery_key(shown['key'], shown['username'])
        else:
            if user_manager.has_recovery_key(user['username']):
                st.success("Your account has a recovery key.")
            else:
                st.warning("Your account has no recovery key yet.")
            st.caption("A recovery key lets you reset a forgotten password without losing "
                       "access to files encrypted with \"Use my password\". Generating a new "
                       "one invalidates the previous one.")

            with st.form("recovery_key_form"):
                password = st.text_input("Confirm your password", type="password")
                if st.form_submit_button("Generate Recovery Key", type="primary"):
                    try:
                        with st.spinner("Generating..."):
                            recovery_key = user_manager.regenerate_recovery_key(
                                user['username'], password)
                    except AuthError as e:
                        st.error(str(e))
                    else:
                        st.session_state.shown_recovery_key = {
                            'context': 'keys',
                            'username': user['username'],
                            'key': recovery_key
                        }
                        st.rerun()


def render_settings_page():
    """Render settings page"""
    st.title("Settings")

    user = st.session_state.current_user
    tab1, tab2 = st.tabs(["Profile", "Security"])

    with tab1:
        with st.form("profile_form"):
            col1, col2 = st.columns(2)
            with col1:
                full_name = st.text_input("Full Name", value=user.get('full_name', ''))
            with col2:
                email = st.text_input("Email", value=user.get('email', ''))

            st.text_input("Username", value=user['username'], disabled=True)

            if st.form_submit_button("Update Profile", type="primary", width="stretch"):
                if full_name.strip() == user.get('full_name') and email.strip() == user.get('email'):
                    st.info("No changes made")
                else:
                    try:
                        profile = user_manager.update_user_profile(user['username'], full_name, email)
                    except AuthError as e:
                        st.error(str(e))
                    else:
                        st.session_state.current_user = profile
                        flash("success", "Profile updated!")
                        st.rerun()

    with tab2:
        with st.form("password_form", clear_on_submit=True):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            st.caption(PASSWORD_RULES)

            if st.form_submit_button("Change Password", type="primary", width="stretch"):
                if not all([current_password, new_password, confirm_password]):
                    st.error("Please fill all fields")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    try:
                        with st.spinner("Updating password..."):
                            user_manager.change_password(user['username'], current_password, new_password)
                    except AuthError as e:
                        st.error(str(e))
                    else:
                        st.success("Password changed successfully! Your files remain accessible.")


def render_help_page():
    """Render help page"""
    st.title("Help & Support")

    with st.expander("Getting Started", expanded=True):
        st.markdown("""
        ### 1. Store Files
        1. Go to **Store Files**
        2. Select a file to upload (or enter a path in Large File mode)
        3. Choose slice size and encryption options
        4. Click **Store File**

        ### 2. Restore Files
        1. Go to **Restore Files**
        2. Select a file from your list
        3. Specify output directory and filename
        4. Provide the decryption key if needed
        5. Click **Restore File** (files up to 200 MB can also be downloaded)
        """)

    with st.expander("Security"):
        st.markdown("""
        ### Encryption
        - Every slice is encrypted with **AES-256-GCM** and bound to its file and position,
          so tampering, reordering or truncation is detected
        - Your password key is a random 256-bit key, stored only in wrapped form and unlocked
          with your password via **PBKDF2-HMAC-SHA256** (600,000 iterations)
        - Passwords are hashed with **bcrypt**

        ### Key Management
        - **Use my password**: changing your password keeps your files accessible
        - **Custom key**: a generated key or a passphrase; it is never stored, so keep it safe
        - **Recovery key**: lets you reset a forgotten password without losing access
        """)

    with st.expander("Troubleshooting"):
        st.markdown("""
        ### Common Issues

        **Can't restore encrypted file**
        Ensure you're using the same key (or passphrase) that was used to store it.

        **Forgot password**
        Use the password reset feature on the login page, together with your recovery key.

        **Changing the theme**
        Use the menu in the top right corner (Settings → Theme).

        **App won't start**
        Ensure port 8501 is not in use, or run `streamlit run app.py --server.port 8502`.
        """)


# ============================================================================
# Main Application
# ============================================================================

PAGES = {
    "dashboard": render_dashboard,
    "storage": render_storage_page,
    "restore": render_restore_page,
    "my_files": render_my_files_page,
    "keys": render_keys_page,
    "settings": render_settings_page,
    "help": render_help_page,
}


def main():
    """Main application entry point"""
    init_session_state()

    if not st.session_state.current_user:
        render_login_page()
        return

    render_sidebar()
    render_flash()
    PAGES.get(st.session_state.current_page, render_dashboard)()


if __name__ == "__main__":
    main()
