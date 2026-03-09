"""
File Storage Manager
"""

import os
import json
import hashlib
import base64
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, BinaryIO
import streamlit as st

# Security libraries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class SecureEncryptor:
    """Encryption handler using AES-GCM"""
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or secrets.token_bytes(32)
        self.aesgcm = AESGCM(self.key)
    
    def encrypt(self, data: bytes) -> Dict:
        """Encrypt data"""
        nonce = secrets.token_bytes(12)
        encrypted = self.aesgcm.encrypt(nonce, data, b"")
        return {
            'data': base64.b64encode(encrypted).decode(),
            'nonce': base64.b64encode(nonce).decode()
        }
    
    def decrypt(self, encrypted_data: Dict) -> bytes:
        """Decrypt data"""
        encrypted = base64.b64decode(encrypted_data['data'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        return self.aesgcm.decrypt(nonce, encrypted, b"")
    
    def get_key_b64(self) -> str:
        """Get base64 encoded key"""
        return base64.b64encode(self.key).decode()

class FileStorageManager:
    """File storage manager with chunked upload support"""
    
    def __init__(self):
        # Storage directories
        self.storage_dir = Path("storage")
        self.index_dir = Path("indexes")
        self.temp_dir = Path("temp_uploads")
        
        self.storage_dir.mkdir(exist_ok=True)
        self.index_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True, parents=True)
        
        # Initialize session state
        if 'file_indexes' not in st.session_state:
            st.session_state.file_indexes = self._load_indexes()
    
    def _load_indexes(self) -> Dict:
        """Load all indexes from disk"""
        indexes = {}
        for index_file in self.index_dir.glob("*.json"):
            try:
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
                    indexes[index_data['file_id']] = index_data
            except:
                continue
        return indexes
    
    def _save_index(self, index_data: Dict):
        """Save index to disk"""
        index_file = self.index_dir / f"{index_data['file_id']}.json"
        with open(index_file, 'w') as f:
            json.dump(index_data, f, indent=2)
        
        # Update session state
        st.session_state.file_indexes[index_data['file_id']] = index_data
    
    def _get_user_indexes(self, username: str) -> List[Dict]:
        """Get indexes for specific user"""
        user_indexes = []
        for index_id, index_data in st.session_state.file_indexes.items():
            if index_data.get('username') == username:
                user_indexes.append({
                    'id': index_id,
                    'name': index_data['file_info']['name'],
                    'size': index_data['file_info']['size'],
                    'created': index_data['created'],
                    'encrypted': index_data['encrypted'],
                    'slices': index_data['total_slices']
                })
        
        # Sort by creation date (newest first)
        user_indexes.sort(key=lambda x: x['created'], reverse=True)
        return user_indexes
    
    def store_file_streaming(self, file_stream, filename: str, total_size: int,
                           slice_mb: int = 10, encrypt_key: Optional[str] = None,
                           progress_callback=None) -> Optional[Dict]:
        """Store file using streaming to handle large files"""
        try:
            # Get current user
            user = st.session_state.current_user
            if not user:
                st.error("No user logged in")
                return None
            
            # Create temporary directory for this upload
            upload_id = f"{int(datetime.now().timestamp())}_{hashlib.md5(filename.encode()).hexdigest()[:8]}"
            temp_upload_dir = self.temp_dir / upload_id
            temp_upload_dir.mkdir(exist_ok=True)
            
            try:
                # Calculate file hash incrementally
                sha256 = hashlib.sha256()
                bytes_processed = 0
                slice_size = slice_mb * 1024 * 1024
                slice_index = 0
                slices_info = []
                
                # Read file in chunks and process immediately
                while True:
                    # Read chunk
                    chunk = file_stream.read(slice_size)
                    if not chunk:
                        break
                    
                    # Update hash
                    sha256.update(chunk)
                    
                    # Save chunk to temporary file for processing
                    temp_chunk_path = temp_upload_dir / f"chunk_{slice_index:06d}.tmp"
                    temp_chunk_path.write_bytes(chunk)
                    
                    # Process this chunk (encrypt if needed)
                    if encrypt_key:
                        try:
                            key = base64.b64decode(encrypt_key)
                            encryptor = SecureEncryptor(key)
                            
                            # Read the temp file and encrypt
                            with open(temp_chunk_path, 'rb') as f:
                                chunk_data = f.read()
                            encrypted = encryptor.encrypt(chunk_data)
                            
                            # Save encrypted chunk
                            slice_id = f"{upload_id}_slice{slice_index:04d}"
                            slice_path = self.storage_dir / f"{slice_id}.enc"
                            with open(slice_path, 'w') as sf:
                                json.dump(encrypted, sf)
                        except Exception as e:
                            st.error(f"Encryption error: {e}")
                            return None
                    else:
                        # Save plain chunk
                        slice_id = f"{upload_id}_slice{slice_index:04d}"
                        slice_path = self.storage_dir / slice_id
                        slice_path.write_bytes(chunk)
                    
                    # Record slice info
                    slices_info.append({
                        'index': slice_index,
                        'id': slice_id,
                        'size': len(chunk),
                        'hash': hashlib.sha256(chunk).hexdigest(),
                        'encrypted': bool(encrypt_key)
                    })
                    
                    slice_index += 1
                    bytes_processed += len(chunk)
                    
                    # Update progress if callback provided
                    if progress_callback:
                        progress_callback(bytes_processed, total_size)
                    
                    # Clean up temp chunk file
                    temp_chunk_path.unlink()
                
                # Final hash
                file_hash = sha256.hexdigest()
                
                # Generate final file ID
                file_id = f"{file_hash[:16]}_{int(datetime.now().timestamp())}"
                
                # Create index data
                index_data = {
                    'file_id': file_id,
                    'file_info': {
                        'name': filename,
                        'size': total_size,
                        'hash': file_hash,
                        'type': 'application/octet-stream'
                    },
                    'slice_size': slice_size,
                    'total_slices': slice_index,
                    'slices': slices_info,
                    'created': datetime.now().isoformat(),
                    'encrypted': bool(encrypt_key),
                    'username': user['username']
                }
                
                # Save index
                self._save_index(index_data)
                
                # Clean up temp directory
                temp_upload_dir.rmdir()
                
                return {
                    'file_id': file_id,
                    'name': filename,
                    'size': total_size,
                    'encrypted': bool(encrypt_key),
                    'slices': slice_index,
                    'created': index_data['created']
                }
                
            except Exception as e:
                # Clean up on error
                if temp_upload_dir.exists():
                    for f in temp_upload_dir.glob("*"):
                        f.unlink()
                    temp_upload_dir.rmdir()
                raise e
                
        except Exception as e:
            st.error(f"Storage error: {str(e)}")
            return None
    
    def store_file(self, uploaded_file, slice_mb: int = 10, 
                   encrypt_key: Optional[str] = None, progress_callback=None) -> Optional[Dict]:
        """Store file (backward compatibility)"""
        # Use streaming method
        return self.store_file_streaming(
            file_stream=uploaded_file,
            filename=uploaded_file.name,
            total_size=uploaded_file.size,
            slice_mb=slice_mb,
            encrypt_key=encrypt_key,
            progress_callback=progress_callback
        )
    
    def store_large_file(self, file_path: str, slice_mb: int = 10,
                        encrypt_key: Optional[str] = None) -> Optional[Dict]:
        """Store large file from disk path"""
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                return self.store_file_streaming(
                    file_stream=f,
                    filename=os.path.basename(file_path),
                    total_size=file_size,
                    slice_mb=slice_mb,
                    encrypt_key=encrypt_key
                )
        except Exception as e:
            st.error(f"Large file storage error: {str(e)}")
            return None
    
    def restore_file(self, file_id: str, output_path: str, 
                     decrypt_key: Optional[str] = None, progress_callback=None) -> bool:
        """Restore file to specified location"""
        try:
            # Get index data
            index_data = st.session_state.file_indexes.get(file_id)
            if not index_data:
                st.error("File index not found")
                return False
            
            # Check encryption
            if index_data['encrypted'] and not decrypt_key:
                st.error("File is encrypted but no key provided")
                return False
            
            # Ensure output directory exists
            output_dir = Path(output_path).parent
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
            
            # Restore slices
            with open(output_path, 'wb') as out_file:
                total_slices = len(index_data['slices'])
                for i, slice_info in enumerate(index_data['slices']):
                    slice_id = slice_info['id']
                    
                    if index_data['encrypted']:
                        # Read encrypted slice
                        slice_path = self.storage_dir / f"{slice_id}.enc"
                        if not slice_path.exists():
                            st.error(f"Missing slice: {slice_id}")
                            return False
                        
                        try:
                            # Decrypt
                            with open(slice_path, 'r') as f:
                                encrypted_data = json.load(f)
                            
                            key = base64.b64decode(decrypt_key)
                            encryptor = SecureEncryptor(key)
                            data = encryptor.decrypt(encrypted_data)
                        except Exception as e:
                            st.error(f"Decryption error: {e}")
                            return False
                    else:
                        # Read plain slice
                        slice_path = self.storage_dir / slice_id
                        if not slice_path.exists():
                            st.error(f"Missing slice: {slice_id}")
                            return False
                        
                        data = slice_path.read_bytes()
                    
                    # Verify hash
                    expected_hash = slice_info['hash']
                    actual_hash = hashlib.sha256(data).hexdigest()
                    
                    if actual_hash != expected_hash:
                        st.error(f"Hash mismatch for slice {slice_info['index']}")
                        return False
                    
                    # Write to output file
                    out_file.write(data)
                    
                    # Update progress if callback provided
                    if progress_callback:
                        progress_callback(i + 1, total_slices)
            
            # Verify restored file
            restored_size = os.path.getsize(output_path)
            if restored_size != index_data['file_info']['size']:
                st.error("Restored file size mismatch")
                return False
            
            return True
            
        except Exception as e:
            st.error(f"Restoration error: {str(e)}")
            return False
    
    def get_storage_stats(self) -> Dict:
        """Get storage statistics"""
        if 'file_indexes' not in st.session_state:
            st.session_state.file_indexes = self._load_indexes()
        
        indexes = st.session_state.file_indexes
        
        total_files = len(indexes)
        total_size = sum(idx['file_info']['size'] for idx in indexes.values())
        encrypted_files = sum(1 for idx in indexes.values() if idx['encrypted'])
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'encrypted_files': encrypted_files
        }
    
    def get_user_files(self, username: str) -> List[Dict]:
        """Get files for specific user"""
        if 'file_indexes' not in st.session_state:
            st.session_state.file_indexes = self._load_indexes()
        
        return self._get_user_indexes(username)