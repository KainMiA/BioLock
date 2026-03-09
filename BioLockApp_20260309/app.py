"""
BioLock - Secure File Storage System
"""

import streamlit as st
import os
import sys
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import random
import string

# Add project root to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import custom modules
from auth_manager import UserManager, SecureKeyManager
from file_storage import FileStorageManager
from utils import format_file_size, validate_email, is_password_strong

# Page configuration
st.set_page_config(
    page_title="BioLock",
    #page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply minimal CSS for theme switching
st.markdown("""
<style>
    /* Minimal styling for theme support */
    .theme-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 500;
        margin-right: 8px;
    }
    
    .theme-light .theme-badge-encrypted {
        background: #e3f2fd;
        color: #1976d2;
    }
    
    .theme-dark .theme-badge-encrypted {
        background: rgba(30, 136, 229, 0.2);
        color: #64b5f6;
    }
    
    .theme-light .theme-badge-plain {
        background: #e8f5e9;
        color: #388e3c;
    }
    
    .theme-dark .theme-badge-plain {
        background: rgba(76, 175, 80, 0.2);
        color: #81c784;
    }
    
    /* File rows */
    .file-row {
        padding: 12px;
        border-radius: 8px;
        margin-bottom: 8px;
    }
    
    .theme-light .file-row {
        background: #f8f9fa;
        border: 1px solid #e9ecef;
    }
    
    .theme-dark .file-row {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #4f46e5, #7c3aed) !important;
    }
    
    /* Metrics styling */
    .metric-card {
        text-align: center;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    
    .theme-light .metric-card {
        background: #f8f9fa;
        border: 1px solid #e9ecef;
    }
    
    .theme-dark .metric-card {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .metric-value {
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 5px;
    }
    
    .theme-light .metric-value {
        color: #1f2937;
    }
    
    .theme-dark .metric-value {
        color: #f9fafb;
    }
    
    .metric-label {
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .theme-light .metric-label {
        color: #6b7280;
    }
    
    .theme-dark .metric-label {
        color: #d1d5db;
    }
    
    /* Card styling */
    .content-card {
        padding: 24px;
        border-radius: 12px;
        margin-bottom: 24px;
    }
    
    .theme-light .content-card {
        background: white;
        border: 1px solid #e5e7eb;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }
    
    .theme-dark .content-card {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# Initialize managers
@st.cache_resource
def init_user_manager():
    return UserManager()

@st.cache_resource
def init_storage_manager():
    return FileStorageManager()

user_manager = init_user_manager()
storage_manager = init_storage_manager()

# ============================================================================
# Helper Functions
# ============================================================================

def generate_verification_code() -> str:
    """Generate a 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_code(email: str, code: str) -> bool:
    """Simulate sending verification code to email"""
    try:
        # Store in session state for demo purposes
        # In production, you would integrate with an email service
        st.session_state.verification_code = code
        st.session_state.verification_email = email
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

def apply_theme(theme: str):
    """Apply theme to the app"""
    st.markdown(f"""
    <script>
    document.body.className = 'theme-{theme}';
    </script>
    """, unsafe_allow_html=True)

def render_sidebar():
    """Render sidebar with theme toggle"""
    with st.sidebar:
        if st.session_state.current_user:
            user = st.session_state.current_user
            
            # User info
            st.markdown(f"### {user['username']}")
            st.caption(f"{user.get('email', '')}")
            #st.divider()
            
            # # Theme toggle
            # col1, col2 = st.columns([3, 1])
            # with col1:
            #     current_theme = st.session_state.get('theme', 'light')
            #     new_theme = 'dark' if current_theme == 'light' else 'light'
                
            #     if st.button(f"{'🌙' if current_theme == 'light' else '☀️'} {new_theme.title()} Mode", 
            #                key="theme_toggle", use_container_width=True):
            #         st.session_state.theme = new_theme
            #         st.rerun()
            
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
                btn_type = "primary" if is_active else "secondary"
                
                if st.button(label, type=btn_type, use_container_width=True, key=f"nav_{page}"):
                    st.session_state.current_page = page
                    st.rerun()
            
            st.divider()
            
            # Logout button
            if st.button("Logout", type="secondary", use_container_width=True):
                user_manager.logout()
                st.rerun()
        else:
            st.info("Please login to continue")

def render_login_page():
    """Render login page"""
    # Apply theme
    #apply_theme(st.session_state.get('theme', 'light'))
    
    # Center the content
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div style='text-align: center; margin-bottom: 40px;'>
            <h1>BioLock</h1>
            <p>Secure Biomedical File Storage with End-to-End Encryption</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Create tabs
        tab1, tab2, tab3 = st.tabs(["Login", "Register", "Reset Password"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                
                if st.form_submit_button("Login", type="primary", use_container_width=True):
                    if username and password:
                        if user_manager.authenticate_user(username, password):
                            st.success("Login successful!")
                            st.session_state.current_page = "dashboard"
                            st.rerun()
                        else:
                            st.error("Invalid username or password")
                    else:
                        st.error("Please fill all fields")
        
        with tab2:
            with st.form("register_form"):
                col1, col2 = st.columns(2)
                with col1:
                    full_name = st.text_input("Full Name", placeholder="Your full name")
                    username = st.text_input("Username", placeholder="Choose username")
                with col2:
                    email = st.text_input("Email", placeholder="your@email.com")
                
                password = st.text_input("Password", type="password", placeholder="Create strong password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")
                
                # Password strength check
                if password:
                    strength = 0
                    if len(password) >= 8:
                        strength += 25
                    if any(c.islower() for c in password):
                        strength += 25
                    if any(c.isupper() for c in password):
                        strength += 25
                    if any(c.isdigit() for c in password):
                        strength += 25
                    
                    st.progress(strength / 100)
                    strength_text = "Weak" if strength < 50 else "Medium" if strength < 75 else "Strong"
                    st.caption(f"Password strength: **{strength_text}**")
                
                if st.form_submit_button("Create Account", type="primary", use_container_width=True):
                    if not all([full_name, email, username, password, confirm_password]):
                        st.error("Please fill all required fields")
                    elif not validate_email(email):
                        st.error("Please enter a valid email address")
                    elif password != confirm_password:
                        st.error("Passwords do not match")
                    elif not is_password_strong(password):
                        st.error("Password must be at least 8 characters with uppercase, lowercase and numbers")
                    elif user_manager.create_user(username, password, email, full_name):
                        st.success("Account created successfully! Please login.")
                    else:
                        st.error("Username already exists")
        
        with tab3:
            with st.form("reset_password_form"):
                email = st.text_input("Email", placeholder="Enter your registered email")
                
                if st.form_submit_button("Send Verification Code", type="primary", use_container_width=True):
                    if email and validate_email(email):
                        # Find user by email
                        user_found = False
                        for username, user_data in user_manager.get_all_users().items():
                            if user_data.get('email') == email:
                                user_found = True
                                code = generate_verification_code()
                                if send_verification_code(email, code):
                                    st.session_state.reset_email = email
                                    st.session_state.reset_code = code
                                    st.session_state.reset_username = username
                                    st.success(f"Verification code sent to {email}")
                                    # For demo purposes, show the code
                                    st.info(f"Verification code: {code} (This would be sent via email)")
                                break
                        
                        if not user_found:
                            st.error("No account found with this email")
                    else:
                        st.error("Please enter a valid email")
            
            # Verification and new password section
            if 'reset_code' in st.session_state:
                with st.form("verify_reset_form"):
                    verification_code = st.text_input("Verification Code", placeholder="Enter 6-digit code")
                    new_password = st.text_input("New Password", type="password", placeholder="New password")
                    confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm new password")
                    
                    if st.form_submit_button("Reset Password", type="primary", use_container_width=True):
                        if verification_code == st.session_state.reset_code:
                            if new_password != confirm_password:
                                st.error("Passwords do not match")
                            elif not is_password_strong(new_password):
                                st.error("Password must be at least 8 characters with uppercase, lowercase and numbers")
                            elif user_manager.reset_password(
                                st.session_state.reset_username,
                                verification_code,
                                new_password
                            ):
                                st.success("Password reset successfully! Please login with your new password.")
                                # Clean up session state
                                del st.session_state.reset_code
                                del st.session_state.reset_email
                                del st.session_state.reset_username
                            else:
                                st.error("Password reset failed")
                        else:
                            st.error("Invalid verification code")

def render_dashboard():
    """Render dashboard"""
    # Apply theme
    #apply_theme(st.session_state.get('theme', 'light'))
    
    # User info
    user = st.session_state.current_user
    
    st.title(f"Welcome back, **{user.get('full_name', user['username'])}**")
    #st.markdown()
    
    # Statistics
    stats = storage_manager.get_storage_stats()
    user_files = storage_manager.get_user_files(user['username'])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{len(user_files)}</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Your Files</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        total_size = sum(f['size'] for f in user_files)
        st.markdown(f'<div class="metric-value">{format_file_size(total_size)}</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Your Storage</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        encrypted_count = sum(1 for f in user_files if f['encrypted'])
        st.markdown(f'<div class="metric-value">{encrypted_count}</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-label">Encrypted</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Recent files
    st.subheader("Recent Files")
    
    if user_files:
        recent_files = user_files[-5:][::-1]  # Get last 5, newest first
        
        for file in recent_files:
            with st.container():
                col1, col2, col3 = st.columns([3, 2, 1])
                with col1:
                    st.write(f"**{file['name']}**")
                    st.caption(f"Stored: {file['created'][:10]}")
                with col2:
                    st.write(format_file_size(file['size']))
                with col3:
                    badge_class = "theme-badge-encrypted" if file['encrypted'] else "theme-badge-plain"
                    badge_text = "Encrypted" if file['encrypted'] else "Plain"
                    st.markdown(f'<span class="theme-badge {badge_class}">{badge_text}</span>', 
                              unsafe_allow_html=True)
    else:
        st.info("No files yet. Store your first file to get started!")

def render_storage_page():
    """Render file storage page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
    st.title("Store File")
    
    upload_mode = st.radio(
        "Upload Mode",
        ["Standard Upload (Up to 200MB)", "Large File Upload (Any Size)"],
        horizontal=True,
        help="Large file mode streams files directly from disk to avoid memory limits"
    )
    
    if upload_mode == "Standard Upload (Up to 200MB)":
        # File upload
        uploaded_file = st.file_uploader(
            "Select file to store",
            type=None,
            help="Choose any file to encrypt and store securely"
        )
        
        file_stream = uploaded_file
        filename = uploaded_file.name if uploaded_file else None
        file_size = uploaded_file.size if uploaded_file else 0
        
    else:  # Large File Upload
        st.info("💡 Large File Mode: Select a file directly from your disk. "
                "Files are processed in chunks without loading into browser memory.")
        
        # File path input for large files
        file_path = st.text_input(
            "File Path",
            placeholder="C:/path/to/your/large/file.dat or /home/user/largefile.dat",
            help="Enter the full path to the file on your computer"
        )
        
        if file_path and os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            # Show file info
            st.success(f"**File found:** {filename} ({format_file_size(file_size)})")
            
            # Create a file stream object
            class FileStream:
                def __init__(self, path):
                    self.path = path
                    self._file = None
                    self.position = 0
                    
                def read(self, size=-1):
                    if not self._file:
                        self._file = open(self.path, 'rb')
                    return self._file.read(size)
                    
                def close(self):
                    if self._file:
                        self._file.close()
                        
                def __enter__(self):
                    return self
                    
                def __exit__(self, exc_type, exc_val, exc_tb):
                    self.close()
            
            file_stream = FileStream(file_path)
        else:
            file_stream = None
            filename = None
            file_size = 0
    
    # Storage options (if file selected)
    if file_stream and filename:
        st.success(f"**File selected:** {filename} ({format_file_size(file_size)})")
        
        # Storage options
        with st.expander("Storage Settings", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                # Adjust slice size based on file size
                if file_size > 1024 * 1024 * 1024:  # >1GB
                    default_slice = 50
                elif file_size > 100 * 1024 * 1024:  # >100MB
                    default_slice = 20
                else:
                    default_slice = 10
                    
                slice_size = st.select_slider(
                    "Slice Size",
                    options=[1, 5, 10, 20, 50, 100, 200, 500],
                    value=default_slice,
                    format_func=lambda x: f"{x} MB"
                )
            
            with col2:
                encryption = st.radio(
                    "Encryption",
                    ["Enabled", "Disabled"],
                    horizontal=True
                )
            
            if encryption == "Enabled":
                key_source = st.radio(
                    "Encryption Key",
                    ["Use my password", "Custom key"],
                    horizontal=True
                )
                
                if key_source == "Use my password":
                    encrypt_key = user_manager.get_current_user_key()
                    st.info("Using key derived from your password")
                else:
                    encrypt_key = st.text_input(
                        "Custom encryption key",
                        type="password",
                        placeholder="Enter your encryption key"
                    )
            else:
                encrypt_key = None
        
        # Store button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("Store File", type="primary", use_container_width=True):
                with st.spinner("Storing file..."):
                    # Create progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    def update_progress(current, total):
                        progress = current / total
                        progress_bar.progress(progress)
                        status_text.text(f"Processing: {format_file_size(current)} / {format_file_size(total)}")
                    
                    # Store file with progress updates
                    if upload_mode == "Standard Upload (Up to 2GB)":
                        result = storage_manager.store_file(
                            uploaded_file=file_stream,
                            slice_mb=slice_size,
                            encrypt_key=encrypt_key,
                            progress_callback=update_progress
                        )
                    else:
                        # For large file mode
                        result = storage_manager.store_file_streaming(
                            file_stream=file_stream,
                            filename=filename,
                            total_size=file_size,
                            slice_mb=slice_size,
                            encrypt_key=encrypt_key,
                            progress_callback=update_progress
                        )
                    
                    # Close file stream for large file mode
                    if upload_mode == "Large File Upload (Any Size)":
                        file_stream.close()
                    
                    progress_bar.empty()
                    status_text.empty()
                    
                    if result:
                        st.success(f"✅ File stored successfully!")
                        st.info(f"File ID: {result['file_id']}")
                        st.balloons()
                    else:
                        st.error("Failed to store file")

def render_restore_page():
    """Render file restoration page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
    st.title("Restore Files")
    
    user = st.session_state.current_user
    user_files = storage_manager.get_user_files(user['username'])
    
    if not user_files:
        st.info("No files available for restoration")
        return
    
    if 'selected_file' not in st.session_state:
        st.session_state.selected_file = None
    
    st.subheader("Select File to Restore")
    
    for file in user_files:
        col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
        with col1:
            st.write(f"**{file['name']}**")
        with col2:
            st.write(format_file_size(file['size']))
        with col3:
            badge_class = "theme-badge-encrypted" if file['encrypted'] else "theme-badge-plain"
            badge_text = "Encrypted" if file['encrypted'] else "Plain"
            st.markdown(f'<span class="theme-badge {badge_class}">{badge_text}</span>', 
                      unsafe_allow_html=True)
        with col4:

            is_selected = (st.session_state.selected_file and 
                          st.session_state.selected_file.get('id') == file['id'])
            
            if st.button("Select" if not is_selected else "✓ Selected", 
                        key=f"select_{file['id']}", 
                        type="primary" if is_selected else "secondary",
                        use_container_width=True):
                st.session_state.selected_file = file
                st.rerun()
        st.divider()
    
    if st.session_state.selected_file:
        selected = st.session_state.selected_file
        
        if selected is None:
            st.error("No file selected. Please select a file from the list above.")

            st.session_state.selected_file = None
            return
            
        st.subheader(f"Restore: {selected['name']}")
        
        with st.form("restore_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                restore_dir = st.text_input(
                    "Output Directory",
                    value="restored",
                    help="Directory to save the restored file"
                )
            
            with col2:
                filename = st.text_input(
                    "Filename",
                    value=selected['name'],
                    help="Name for the restored file"
                )
            
            output_path = os.path.join(restore_dir, filename)
            
            if selected['encrypted']:
                st.warning("⚠️ This file is encrypted")
                key_source = st.radio(
                    "Decryption Key",
                    ["Use my password", "Custom key"],
                    horizontal=True
                )
                
                if key_source == "Use my password":
                    decrypt_key = user_manager.get_current_user_key()
                    st.info("Using key derived from your password")
                else:
                    decrypt_key = st.text_input(
                        "Enter decryption key",
                        type="password",
                        placeholder="Paste your decryption key"
                    )
            else:
                decrypt_key = None
            
            col1, col2 = st.columns(2)
            
            form_col1, form_col2 = st.columns(2)
            
            with form_col1:
                restore_submitted = st.form_submit_button(
                    "Restore File", 
                    type="primary", 
                    use_container_width=True
                )
            
            with form_col2:
                cancel_submitted = st.form_submit_button(
                    "Cancel", 
                    type="secondary", 
                    use_container_width=True
                )
            
            if restore_submitted:

                validation_errors = []
                
                if not restore_dir:
                    validation_errors.append("Please specify output directory")
                if not filename:
                    validation_errors.append("Please specify filename")
                if selected['encrypted'] and not decrypt_key:
                    validation_errors.append("Encrypted file requires decryption key")
                
                if validation_errors:
                    for error in validation_errors:
                        st.error(error)
                else:
                    with st.spinner("Restoring file..."):
                        success = storage_manager.restore_file(
                            file_id=selected['id'],
                            output_path=output_path,
                            decrypt_key=decrypt_key
                        )
                        
                        if success:
                            st.success(f"✅ File restored to: `{output_path}`")
                            
                            if os.path.exists(output_path):
                                file_size = os.path.getsize(output_path)
                                st.info(f"File size: {format_file_size(file_size)}")
                                st.balloons()
                            
                            # Clear selection after successful restoration
                            st.session_state.selected_file = None
                        else:
                            st.error("Failed to restore file")
            
            if cancel_submitted:
                # Clear selection
                st.session_state.selected_file = None
                st.rerun()
    else:

        st.info("👆 Select a file from the list above to restore it")

def render_my_files_page():
    """Render user files page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
    st.title("My Files")
    
    user = st.session_state.current_user
    user_files = storage_manager.get_user_files(user['username'])
    
    if user_files:
        # Summary
        total_size = sum(f['size'] for f in user_files)
        encrypted_count = sum(1 for f in user_files if f['encrypted'])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Files", len(user_files))
        with col2:
            st.metric("Total Size", format_file_size(total_size))
        with col3:
            st.metric("Encrypted", encrypted_count)
        
        st.divider()
        
        # Search
        search_query = st.text_input("Search files", placeholder="Type to search...")
        
        # Filter files
        filtered_files = user_files
        if search_query:
            filtered_files = [f for f in filtered_files if search_query.lower() in f['name'].lower()]
        
        # Display files
        if filtered_files:
            for file in filtered_files:
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                    with col1:
                        st.write(f"**{file['name']}**")
                        st.caption(f"ID: {file['id'][:12]}... • Stored: {file['created'][:10]}")
                    with col2:
                        st.write(format_file_size(file['size']))
                    with col3:
                        badge_class = "theme-badge-encrypted" if file['encrypted'] else "theme-badge-plain"
                        badge_text = "Encrypted" if file['encrypted'] else "Plain"
                        st.markdown(f'<span class="theme-badge {badge_class}">{badge_text}</span>', 
                                  unsafe_allow_html=True)
                    with col4:
                        if st.button("Restore", key=f"restore_{file['id']}", use_container_width=True):
                            st.session_state.selected_file = file
                            st.session_state.current_page = "restore"
                            st.rerun()
                    st.divider()
        else:
            st.info("No files match your search")
    else:
        st.info("You haven't stored any files yet")
        if st.button("Store Your First File", type="primary"):
            st.session_state.current_page = "storage"
            st.rerun()

def render_keys_page():
    """Render key management page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
    st.title("Encryption Keys")
    
    tab1, tab2 = st.tabs(["Password Key", "Custom Keys"])
    
    with tab1:
        st.subheader("Password-Derived Key")
        
        user_key = user_manager.get_current_user_key()
        if user_key:
            st.info("This key is automatically derived from your password.")
            
            col1, col2 = st.columns([3, 1])
            with col1:
                st.text_input(
                    "Your Key",
                    value="•" * 40,
                    type="password",
                    disabled=True,
                    label_visibility="collapsed"
                )
            
            with col2:
                if st.button("Show Key", use_container_width=True):
                    st.text_input(
                        "Your Key",
                        value=user_key,
                        disabled=True,
                        label_visibility="collapsed"
                    )
        else:
            st.warning("Unable to retrieve key")
    
    with tab2:
        st.subheader("Custom Keys")
        
        if st.button("Generate New Key", type="primary", use_container_width=True):
            new_key = SecureKeyManager.generate_encryption_key()
            st.session_state.new_key = new_key
        
        if 'new_key' in st.session_state:
            st.text_area(
                "Generated Key",
                value=st.session_state.new_key,
                height=100,
                disabled=True,
                help="Save this key securely!"
            )
            
            col1, col2 = st.columns(2)
            with col1:
                try:
                    import pyperclip
                    if st.button("Copy to Clipboard", use_container_width=True):
                        pyperclip.copy(st.session_state.new_key)
                        st.success("Copied!")
                except:
                    st.warning("Install pyperclip for copy functionality")
            
            with col2:
                key_data = json.dumps({
                    "key": st.session_state.new_key,
                    "generated": datetime.now().isoformat(),
                    "user": st.session_state.current_user['username']
                }, indent=2)
                
                st.download_button(
                    "Save Key File",
                    data=key_data,
                    file_name=f"key_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            st.warning("⚠️ Save this key securely! Lost keys cannot recover encrypted files.")

def render_settings_page():
    """Render settings page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
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
            
            username = st.text_input("Username", value=user['username'], disabled=True)
            
            if st.form_submit_button("Update Profile", type="primary", use_container_width=True):
                updates = {}
                if full_name != user.get('full_name'):
                    updates['full_name'] = full_name
                if email != user.get('email'):
                    if validate_email(email):
                        updates['email'] = email
                    else:
                        st.error("Invalid email address")
                
                if updates:
                    if user_manager.update_user_profile(user['username'], updates):
                        st.success("Profile updated!")
                        # Update session
                        for key, value in updates.items():
                            st.session_state.current_user[key] = value
                        st.rerun()
                    else:
                        st.error("Failed to update profile")
                else:
                    st.info("No changes made")
    
    with tab2:
        with st.form("password_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            
            if st.form_submit_button("Change Password", type="primary", use_container_width=True):
                if not all([current_password, new_password, confirm_password]):
                    st.error("Please fill all fields")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                elif not is_password_strong(new_password):
                    st.error("Password must be at least 8 characters with mixed case and numbers")
                elif user_manager.change_password(user['username'], current_password, new_password):
                    st.success("Password changed successfully!")
                else:
                    st.error("Incorrect current password")

def render_help_page():
    """Render help page"""
    # Apply theme
    apply_theme(st.session_state.get('theme', 'light'))
    
    st.title("Help & Support")
    
    with st.expander("Getting Started", expanded=True):
        st.markdown("""
        ### 1. Store Files
        1. Go to **Store Files**
        2. Select a file to upload
        3. Choose encryption options
        4. Click **Store File**
        
        ### 2. Restore Files
        1. Go to **Restore Files**
        2. Select a file from your list
        3. Specify output directory and filename
        4. Provide decryption key if needed
        5. Click **Restore File**
        """)
    
    with st.expander("Security"):
        st.markdown("""
        ### Encryption
        - Files are encrypted using **AES-256-GCM**
        - Keys are derived from your password using **PBKDF2**
        - Each file slice has unique encryption
        
        ### Key Management
        - Your password automatically creates an encryption key
        - You can generate custom keys for specific files
        - **IMPORTANT**: Save custom keys securely!
        """)
    
    with st.expander("Troubleshooting"):
        st.markdown("""
        ### Common Issues
        
        **Can't restore encrypted file**  
        Ensure you're using the correct encryption key.
        
        **Forgot password**  
        Use the password reset feature on the login page.
        
        **App won't start**  
        Ensure port 8501 is not in use.
        """)

# ============================================================================
# Main Application
# ============================================================================

def main():
    """Main application entry point"""
    
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "dashboard"
    
    if 'theme' not in st.session_state:
        st.session_state.theme = "light"  # Default to light theme
    
    if 'selected_file' not in st.session_state:
        st.session_state.selected_file = None
    
    # Check login status
    if not st.session_state.current_user:
        render_login_page()
    else:
        # Render sidebar
        render_sidebar()
        
        # Render main content
        main_container = st.container()
        
        with main_container:
            page = st.session_state.current_page
            
            if page == "dashboard":
                render_dashboard()
            elif page == "storage":
                render_storage_page()
            elif page == "restore":
                render_restore_page()
            elif page == "my_files":
                render_my_files_page()
            elif page == "keys":
                render_keys_page()
            elif page == "settings":
                render_settings_page()
            elif page == "help":
                render_help_page()

if __name__ == "__main__":
    main()