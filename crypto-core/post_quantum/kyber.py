"""
ML-KEM (Kyber) post-quantum key encapsulation mechanism implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

logger = logging.getLogger(__name__)

class KyberVariant:
    """Kyber/ML-KEM variant configurations."""
    
    KYBER_512 = {
        "name": "ML-KEM-512",
        "module": ml_kem_512,
        "security_level": 128,
        "public_key_size": ml_kem_512.PUBLIC_KEY_SIZE,
        "private_key_size": ml_kem_512.SECRET_KEY_SIZE,
        "ciphertext_size": ml_kem_512.CIPHERTEXT_SIZE,
        "shared_secret_size": ml_kem_512.PLAINTEXT_SIZE,
        "nist_level": 1
    }
    
    KYBER_768 = {
        "name": "ML-KEM-768",
        "module": ml_kem_768,
        "security_level": 192,
        "public_key_size": ml_kem_768.PUBLIC_KEY_SIZE,
        "private_key_size": ml_kem_768.SECRET_KEY_SIZE,
        "ciphertext_size": ml_kem_768.CIPHERTEXT_SIZE,
        "shared_secret_size": ml_kem_768.PLAINTEXT_SIZE,
        "nist_level": 3
    }
    
    KYBER_1024 = {
        "name": "ML-KEM-1024",
        "module": ml_kem_1024,
        "security_level": 256,
        "public_key_size": ml_kem_1024.PUBLIC_KEY_SIZE,
        "private_key_size": ml_kem_1024.SECRET_KEY_SIZE,
        "ciphertext_size": ml_kem_1024.CIPHERTEXT_SIZE,
        "shared_secret_size": ml_kem_1024.PLAINTEXT_SIZE,
        "nist_level": 5
    }

class KyberKEM:
    """ML-KEM (Kyber) Key Encapsulation Mechanism using certified pqcrypto library."""
    
    def __init__(self, variant: str = "kyber1024"):
        """Initialize ML-KEM with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified ML-KEM variant."""
        variant_map = {
            "kyber512": KyberVariant.KYBER_512,
            "kyber768": KyberVariant.KYBER_768,
            "kyber1024": KyberVariant.KYBER_1024,
            "ml_kem_512": KyberVariant.KYBER_512,
            "ml_kem_768": KyberVariant.KYBER_768,
            "ml_kem_1024": KyberVariant.KYBER_1024
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported ML-KEM/Kyber variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate an ML-KEM keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"ML-KEM keypair generation failed: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        try:
            if len(public_key) != self.config["public_key_size"]:
                raise ValueError(f"Invalid public key size: {len(public_key)}, "
                               f"expected {self.config['public_key_size']}")
            
            ciphertext, shared_secret = self.module.encrypt(public_key)
            
            logger.info(f"ML-KEM encapsulation completed")
            logger.debug(f"Ciphertext: {len(ciphertext)} bytes, "
                        f"Shared secret: {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
            
        except Exception as e:
            logger.error(f"ML-KEM encapsulation failed: {e}")
            raise
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret using private key."""
        try:
            if len(private_key) != self.config["private_key_size"]:
                raise ValueError(f"Invalid private key size: {len(private_key)}, "
                               f"expected {self.config['private_key_size']}")
            
            if len(ciphertext) != self.config["ciphertext_size"]:
                raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}, "
                               f"expected {self.config['ciphertext_size']}")
            
            shared_secret = self.module.decrypt(private_key, ciphertext)
            
            logger.info(f"ML-KEM decapsulation completed")
            logger.debug(f"Shared secret: {len(shared_secret)} bytes")
            
            return shared_secret
            
        except Exception as e:
            logger.error(f"ML-KEM decapsulation failed: {e}")
            raise
    
    def get_key_sizes(self) -> Dict[str, int]:
        """Get key and ciphertext sizes for current parameters."""
        return {
            "public_key_size": self.config["public_key_size"],
            "private_key_size": self.config["private_key_size"],
            "ciphertext_size": self.config["ciphertext_size"],
            "shared_secret_size": self.config["shared_secret_size"]
        }
    
    def get_security_level(self) -> int:
        """Get security level in bits."""
        return self.config["security_level"]
    
    def get_nist_level(self) -> int:
        """Get NIST security level."""
        return self.config["nist_level"]
    
    def get_algorithm_name(self) -> str:
        """Get the official algorithm name."""
        return self.config["name"]
    
    def serialize_public_key(self, public_key: bytes) -> str:
        """Serialize public key to base64 string."""
        return base64.b64encode(public_key).decode('utf-8')
    
    def deserialize_public_key(self, public_key_str: str) -> bytes:
        """Deserialize public key from base64 string."""
        try:
            return base64.b64decode(public_key_str.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid public key format: {e}")
    
    def serialize_private_key(self, private_key: bytes) -> str:
        """Serialize private key to base64 string."""
        return base64.b64encode(private_key).decode('utf-8')
    
    def deserialize_private_key(self, private_key_str: str) -> bytes:
        """Deserialize private key from base64 string."""
        try:
            return base64.b64decode(private_key_str.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid private key format: {e}")
    
    def serialize_ciphertext(self, ciphertext: bytes) -> str:
        """Serialize ciphertext to base64 string."""
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def deserialize_ciphertext(self, ciphertext_str: str) -> bytes:
        """Deserialize ciphertext from base64 string."""
        try:
            return base64.b64decode(ciphertext_str.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid ciphertext format: {e}")
    
    def serialize_shared_secret(self, shared_secret: bytes) -> str:
        """Serialize shared secret to base64 string."""
        return base64.b64encode(shared_secret).decode('utf-8')
    
    def deserialize_shared_secret(self, shared_secret_str: str) -> bytes:
        """Deserialize shared secret from base64 string."""
        try:
            return base64.b64decode(shared_secret_str.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid shared secret format: {e}")

# Convenience functions for backward compatibility
def generate_kyber_keypair(variant: str = "kyber1024") -> Tuple[str, str]:
    """Generate ML-KEM keypair and return as base64 strings."""
    kyber = KyberKEM(variant)
    public_key, private_key = kyber.generate_keypair()
    
    return (
        kyber.serialize_public_key(public_key),
        kyber.serialize_private_key(private_key)
    )

def kyber_encapsulate(public_key_str: str, variant: str = "kyber1024") -> Tuple[str, str]:
    """Encapsulate using ML-KEM and return ciphertext and shared secret as base64."""
    kyber = KyberKEM(variant)
    public_key = kyber.deserialize_public_key(public_key_str)
    
    ciphertext, shared_secret = kyber.encapsulate(public_key)
    
    return (
        kyber.serialize_ciphertext(ciphertext),
        kyber.serialize_shared_secret(shared_secret)
    )

def kyber_decapsulate(private_key_str: str, ciphertext_str: str, 
                     variant: str = "kyber1024") -> str:
    """Decapsulate using ML-KEM and return shared secret as base64."""
    kyber = KyberKEM(variant)
    private_key = kyber.deserialize_private_key(private_key_str)
    ciphertext = kyber.deserialize_ciphertext(ciphertext_str)
    
    shared_secret = kyber.decapsulate(private_key, ciphertext)
    
    return kyber.serialize_shared_secret(shared_secret)

def get_kyber_info(variant: str = "kyber1024") -> Dict[str, Any]:
    """Get information about ML-KEM variant."""
    kyber = KyberKEM(variant)
    
    return {
        "variant": variant,
        "algorithm_name": kyber.get_algorithm_name(),
        "security_level": kyber.get_security_level(),
        "nist_level": kyber.get_nist_level(),
        "key_sizes": kyber.get_key_sizes(),
        "quantum_resistant": True,
        "algorithm_type": "Key Encapsulation Mechanism",
        "standardization": "NIST FIPS 203",
        "description": "NIST-standardized post-quantum key encapsulation mechanism"
    }

def get_supported_kyber_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported ML-KEM variants."""
    return {
        "kyber512": {
            "name": "ML-KEM-512",
            "security_level": 128,
            "nist_level": 1,
            "key_sizes": KyberVariant.KYBER_512
        },
        "kyber768": {
            "name": "ML-KEM-768",
            "security_level": 192,
            "nist_level": 3,
            "key_sizes": KyberVariant.KYBER_768
        },
        "kyber1024": {
            "name": "ML-KEM-1024",
            "security_level": 256,
            "nist_level": 5,
            "key_sizes": KyberVariant.KYBER_1024
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing ML-KEM (Kyber) certified implementation...")
    
    # Test all variants
    for variant in ["kyber512", "kyber768", "kyber1024"]:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_kyber_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Encapsulate
        ciphertext, shared_secret1 = kyber_encapsulate(public_key, variant)
        print(f"Ciphertext: {ciphertext[:50]}...")
        print(f"Shared secret 1: {shared_secret1}")
        
        # Decapsulate
        shared_secret2 = kyber_decapsulate(private_key, ciphertext, variant)
        print(f"Shared secret 2: {shared_secret2}")
        
        # Verify shared secrets match
        print(f"Shared secrets match: {shared_secret1 == shared_secret2}")
        
        # Get algorithm info
        info = get_kyber_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"NIST level: {info['nist_level']}")
    
    print("\n=== Supported Variants ===")
    variants = get_supported_kyber_variants()
    for name, info in variants.items():
        print(f"{name}: {info['name']} (Security: {info['security_level']} bits)")