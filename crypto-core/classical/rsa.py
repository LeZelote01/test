"""
RSA classical cryptography implementation for QuantumGate.
"""
import base64
import logging
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import time

logger = logging.getLogger(__name__)

class RSACrypto:
    """RSA cryptographic operations."""
    
    def __init__(self, key_size: int = 2048):
        """Initialize RSA with specified key size."""
        self.key_size = key_size
        self.backend = default_backend()
        
        # Validate key size
        if key_size not in [2048, 3072, 4096]:
            raise ValueError(f"Unsupported RSA key size: {key_size}")
    
    def generate_keypair(self) -> Tuple[str, str]:
        """Generate RSA keypair and return as PEM strings."""
        try:
            start_time = time.time()
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=self.backend
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            generation_time = time.time() - start_time
            
            logger.info(f"Generated RSA-{self.key_size} keypair in {generation_time:.3f}s")
            
            return (
                base64.b64encode(public_pem).decode('utf-8'),
                base64.b64encode(private_pem).decode('utf-8')
            )
            
        except Exception as e:
            logger.error(f"RSA keypair generation failed: {e}")
            raise
    
    def encrypt(self, data: str, public_key_str: str) -> str:
        """Encrypt data using RSA public key."""
        try:
            start_time = time.time()
            
            # Load public key
            public_key_pem = base64.b64decode(public_key_str.encode('utf-8'))
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            # Check data size limit
            max_data_size = (self.key_size // 8) - 2 * 32 - 2  # OAEP padding overhead
            if len(data.encode('utf-8')) > max_data_size:
                raise ValueError(f"Data too large for RSA-{self.key_size} encryption")
            
            # Encrypt data
            ciphertext = public_key.encrypt(
                data.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            encryption_time = time.time() - start_time
            
            logger.info(f"RSA encryption completed in {encryption_time:.3f}s")
            
            return base64.b64encode(ciphertext).decode('utf-8')
            
        except Exception as e:
            logger.error(f"RSA encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_data: str, private_key_str: str) -> str:
        """Decrypt data using RSA private key."""
        try:
            start_time = time.time()
            
            # Load private key
            private_key_pem = base64.b64decode(private_key_str.encode('utf-8'))
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            
            # Decrypt data
            ciphertext = base64.b64decode(encrypted_data.encode('utf-8'))
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            decryption_time = time.time() - start_time
            
            logger.info(f"RSA decryption completed in {decryption_time:.3f}s")
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logger.error(f"RSA decryption failed: {e}")
            raise
    
    def sign(self, data: str, private_key_str: str) -> str:
        """Sign data using RSA private key."""
        try:
            start_time = time.time()
            
            # Load private key
            private_key_pem = base64.b64decode(private_key_str.encode('utf-8'))
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            
            # Sign data
            signature = private_key.sign(
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signing_time = time.time() - start_time
            
            logger.info(f"RSA signing completed in {signing_time:.3f}s")
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"RSA signing failed: {e}")
            raise
    
    def verify(self, data: str, signature_str: str, public_key_str: str) -> bool:
        """Verify signature using RSA public key."""
        try:
            start_time = time.time()
            
            # Load public key
            public_key_pem = base64.b64decode(public_key_str.encode('utf-8'))
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            # Verify signature
            signature = base64.b64decode(signature_str.encode('utf-8'))
            
            public_key.verify(
                signature,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            verification_time = time.time() - start_time
            
            logger.info(f"RSA verification completed in {verification_time:.3f}s: valid")
            
            return True
            
        except InvalidSignature:
            logger.info(f"RSA signature verification: invalid")
            return False
        except Exception as e:
            logger.error(f"RSA verification failed: {e}")
            return False
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get RSA key information."""
        return {
            "algorithm": "RSA",
            "key_size": self.key_size,
            "security_level": min(self.key_size // 8, 256),  # Simplified mapping
            "quantum_resistant": False,
            "max_data_size": (self.key_size // 8) - 2 * 32 - 2,
            "use_cases": [
                "Digital signatures",
                "Key exchange",
                "Legacy system compatibility"
            ],
            "performance": {
                "keygen_time": 0.05 * (self.key_size / 2048),
                "encrypt_time": 0.001,
                "decrypt_time": 0.02 * (self.key_size / 2048),
                "sign_time": 0.02 * (self.key_size / 2048),
                "verify_time": 0.001
            }
        }

# Convenience functions
def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """Generate RSA keypair."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.generate_keypair()

def rsa_encrypt(data: str, public_key: str, key_size: int = 2048) -> str:
    """Encrypt data using RSA."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.encrypt(data, public_key)

def rsa_decrypt(encrypted_data: str, private_key: str, key_size: int = 2048) -> str:
    """Decrypt data using RSA."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.decrypt(encrypted_data, private_key)

def rsa_sign(data: str, private_key: str, key_size: int = 2048) -> str:
    """Sign data using RSA."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.sign(data, private_key)

def rsa_verify(data: str, signature: str, public_key: str, key_size: int = 2048) -> bool:
    """Verify signature using RSA."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.verify(data, signature, public_key)

def get_rsa_info(key_size: int = 2048) -> Dict[str, Any]:
    """Get RSA algorithm information."""
    rsa_crypto = RSACrypto(key_size)
    return rsa_crypto.get_key_info()

# Example usage
if __name__ == "__main__":
    # Test RSA implementation
    print("Testing RSA implementation...")
    
    # Generate keypair
    public_key, private_key = generate_rsa_keypair(2048)
    print(f"Generated RSA-2048 keypair")
    
    # Test encryption/decryption
    test_data = "Hello, RSA world!"
    encrypted = rsa_encrypt(test_data, public_key, 2048)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = rsa_decrypt(encrypted, private_key, 2048)
    print(f"Decrypted: {decrypted}")
    print(f"Encryption/decryption successful: {test_data == decrypted}")
    
    # Test signing/verification
    signature = rsa_sign(test_data, private_key, 2048)
    print(f"Signature: {signature[:50]}...")
    
    is_valid = rsa_verify(test_data, signature, public_key, 2048)
    print(f"Signature valid: {is_valid}")
    
    # Test with wrong data
    wrong_data = "Wrong data"
    is_valid_wrong = rsa_verify(wrong_data, signature, public_key, 2048)
    print(f"Wrong data signature valid: {is_valid_wrong}")
    
    # Get algorithm info
    info = get_rsa_info(2048)
    print(f"Algorithm info: {info}")