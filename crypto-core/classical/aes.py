"""
AES classical cryptography implementation for QuantumGate.
"""
import base64
import secrets
import logging
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time

logger = logging.getLogger(__name__)

class AESCrypto:
    """AES cryptographic operations."""
    
    def __init__(self, key_size: int = 256, mode: str = "CBC"):
        """Initialize AES with specified key size and mode."""
        self.key_size = key_size
        self.mode = mode
        self.backend = default_backend()
        
        # Validate key size
        if key_size not in [128, 192, 256]:
            raise ValueError(f"Unsupported AES key size: {key_size}")
        
        # Validate mode
        if mode not in ["CBC", "GCM", "CTR"]:
            raise ValueError(f"Unsupported AES mode: {mode}")
    
    def generate_key(self, password: Optional[str] = None) -> str:
        """Generate AES key."""
        try:
            if password:
                # Derive key from password
                salt = secrets.token_bytes(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self.key_size // 8,
                    salt=salt,
                    iterations=100000,
                    backend=self.backend
                )
                key = kdf.derive(password.encode())
                # Return key with salt for later use
                return base64.b64encode(salt + key).decode('utf-8')
            else:
                # Generate random key
                key = secrets.token_bytes(self.key_size // 8)
                return base64.b64encode(key).decode('utf-8')
                
        except Exception as e:
            logger.error(f"AES key generation failed: {e}")
            raise
    
    def encrypt(self, data: str, key_str: str) -> str:
        """Encrypt data using AES."""
        try:
            start_time = time.time()
            
            # Decode key
            key_bytes = base64.b64decode(key_str.encode('utf-8'))
            
            # If key was derived from password, extract actual key
            if len(key_bytes) > (self.key_size // 8):
                salt = key_bytes[:16]
                key = key_bytes[16:]
            else:
                key = key_bytes
            
            # Convert data to bytes
            data_bytes = data.encode('utf-8')
            
            if self.mode == "CBC":
                ciphertext = self._encrypt_cbc(data_bytes, key)
            elif self.mode == "GCM":
                ciphertext = self._encrypt_gcm(data_bytes, key)
            elif self.mode == "CTR":
                ciphertext = self._encrypt_ctr(data_bytes, key)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
            
            encryption_time = time.time() - start_time
            
            logger.info(f"AES-{self.key_size} {self.mode} encryption completed in {encryption_time:.3f}s")
            
            return base64.b64encode(ciphertext).decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: str, key_str: str) -> str:
        """Decrypt data using AES."""
        try:
            start_time = time.time()
            
            # Decode key and ciphertext
            key_bytes = base64.b64decode(key_str.encode('utf-8'))
            ciphertext = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # If key was derived from password, extract actual key
            if len(key_bytes) > (self.key_size // 8):
                salt = key_bytes[:16]
                key = key_bytes[16:]
            else:
                key = key_bytes
            
            if self.mode == "CBC":
                plaintext = self._decrypt_cbc(ciphertext, key)
            elif self.mode == "GCM":
                plaintext = self._decrypt_gcm(ciphertext, key)
            elif self.mode == "CTR":
                plaintext = self._decrypt_ctr(ciphertext, key)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
            
            decryption_time = time.time() - start_time
            
            logger.info(f"AES-{self.key_size} {self.mode} decryption completed in {decryption_time:.3f}s")
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            raise
    
    def _encrypt_cbc(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-CBC mode."""
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def _decrypt_cbc(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using AES-CBC mode."""
        # Extract IV and ciphertext
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad data
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def _encrypt_gcm(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-GCM mode."""
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return nonce + tag + ciphertext
        return nonce + encryptor.tag + ciphertext
    
    def _decrypt_gcm(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using AES-GCM mode."""
        # Extract nonce, tag, and ciphertext
        nonce = ciphertext[:12]
        tag = ciphertext[12:28]
        encrypted_data = ciphertext[28:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return data
    
    def _encrypt_ctr(self, data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-CTR mode."""
        # Generate random nonce
        nonce = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def _decrypt_ctr(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using AES-CTR mode."""
        # Extract nonce and ciphertext
        nonce = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return data
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get AES key information."""
        return {
            "algorithm": "AES",
            "key_size": self.key_size,
            "mode": self.mode,
            "security_level": min(self.key_size, 256),
            "quantum_resistant": False,
            "block_size": 128,
            "use_cases": [
                "Symmetric encryption",
                "Secure storage",
                "Network security",
                "Fast encryption"
            ],
            "performance": {
                "encrypt_time": 0.001,
                "decrypt_time": 0.001,
                "throughput": "high"
            }
        }

# Convenience functions
def generate_aes_key(key_size: int = 256, password: Optional[str] = None) -> str:
    """Generate AES key."""
    aes_crypto = AESCrypto(key_size)
    return aes_crypto.generate_key(password)

def aes_encrypt(data: str, key: str, key_size: int = 256, mode: str = "CBC") -> str:
    """Encrypt data using AES."""
    aes_crypto = AESCrypto(key_size, mode)
    return aes_crypto.encrypt(data, key)

def aes_decrypt(encrypted_data: str, key: str, key_size: int = 256, mode: str = "CBC") -> str:
    """Decrypt data using AES."""
    aes_crypto = AESCrypto(key_size, mode)
    return aes_crypto.decrypt(encrypted_data, key)

def get_aes_info(key_size: int = 256, mode: str = "CBC") -> Dict[str, Any]:
    """Get AES algorithm information."""
    aes_crypto = AESCrypto(key_size, mode)
    return aes_crypto.get_key_info()

# Example usage
if __name__ == "__main__":
    # Test AES implementation
    print("Testing AES implementation...")
    
    # Generate key
    key = generate_aes_key(256)
    print(f"Generated AES-256 key")
    
    # Test encryption/decryption
    test_data = "Hello, AES world! This is a longer message to test AES encryption."
    encrypted = aes_encrypt(test_data, key, 256, "CBC")
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = aes_decrypt(encrypted, key, 256, "CBC")
    print(f"Decrypted: {decrypted}")
    print(f"Encryption/decryption successful: {test_data == decrypted}")
    
    # Test with password-derived key
    password_key = generate_aes_key(256, "mypassword123")
    encrypted_pwd = aes_encrypt(test_data, password_key, 256, "CBC")
    decrypted_pwd = aes_decrypt(encrypted_pwd, password_key, 256, "CBC")
    print(f"Password-based encryption successful: {test_data == decrypted_pwd}")
    
    # Test different modes
    for mode in ["CBC", "GCM", "CTR"]:
        print(f"\nTesting {mode} mode...")
        encrypted_mode = aes_encrypt(test_data, key, 256, mode)
        decrypted_mode = aes_decrypt(encrypted_mode, key, 256, mode)
        print(f"{mode} successful: {test_data == decrypted_mode}")
    
    # Get algorithm info
    info = get_aes_info(256, "CBC")
    print(f"Algorithm info: {info}")