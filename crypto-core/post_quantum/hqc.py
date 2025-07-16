"""
HQC (Hamming Quasi-Cyclic) post-quantum key encapsulation mechanism implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
HQC was selected by NIST in March 2025 as a backup to ML-KEM.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.kem import hqc_128, hqc_192, hqc_256

logger = logging.getLogger(__name__)

class HQCVariant:
    """HQC variant configurations."""
    
    HQC_128 = {
        "name": "HQC-128",
        "module": hqc_128,
        "security_level": 128,
        "public_key_size": hqc_128.PUBLIC_KEY_SIZE,
        "private_key_size": hqc_128.SECRET_KEY_SIZE,
        "ciphertext_size": hqc_128.CIPHERTEXT_SIZE,
        "shared_secret_size": hqc_128.PLAINTEXT_SIZE,
        "nist_level": 1,
        "description": "Code-based cryptography using error-correcting codes"
    }
    
    HQC_192 = {
        "name": "HQC-192",
        "module": hqc_192,
        "security_level": 192,
        "public_key_size": hqc_192.PUBLIC_KEY_SIZE,
        "private_key_size": hqc_192.SECRET_KEY_SIZE,
        "ciphertext_size": hqc_192.CIPHERTEXT_SIZE,
        "shared_secret_size": hqc_192.PLAINTEXT_SIZE,
        "nist_level": 3,
        "description": "Code-based cryptography using error-correcting codes"
    }
    
    HQC_256 = {
        "name": "HQC-256",
        "module": hqc_256,
        "security_level": 256,
        "public_key_size": hqc_256.PUBLIC_KEY_SIZE,
        "private_key_size": hqc_256.SECRET_KEY_SIZE,
        "ciphertext_size": hqc_256.CIPHERTEXT_SIZE,
        "shared_secret_size": hqc_256.PLAINTEXT_SIZE,
        "nist_level": 5,
        "description": "Code-based cryptography using error-correcting codes"
    }

class HQCKEM:
    """HQC Key Encapsulation Mechanism using certified pqcrypto library."""
    
    def __init__(self, variant: str = "hqc_256"):
        """Initialize HQC with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified HQC variant."""
        variant_map = {
            "hqc_128": HQCVariant.HQC_128,
            "hqc_192": HQCVariant.HQC_192,
            "hqc_256": HQCVariant.HQC_256,
            "hqc128": HQCVariant.HQC_128,
            "hqc192": HQCVariant.HQC_192,
            "hqc256": HQCVariant.HQC_256
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported HQC variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate an HQC keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"HQC keypair generation failed: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        try:
            if len(public_key) != self.config["public_key_size"]:
                raise ValueError(f"Invalid public key size: {len(public_key)}, "
                               f"expected {self.config['public_key_size']}")
            
            ciphertext, shared_secret = self.module.encrypt(public_key)
            
            logger.info(f"HQC encapsulation completed")
            logger.debug(f"Ciphertext: {len(ciphertext)} bytes, "
                        f"Shared secret: {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
            
        except Exception as e:
            logger.error(f"HQC encapsulation failed: {e}")
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
            
            logger.info(f"HQC decapsulation completed")
            logger.debug(f"Shared secret: {len(shared_secret)} bytes")
            
            return shared_secret
            
        except Exception as e:
            logger.error(f"HQC decapsulation failed: {e}")
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
        """Get the algorithm name."""
        return self.config["name"]
    
    def get_description(self) -> str:
        """Get algorithm description."""
        return self.config["description"]
    
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

# Convenience functions
def generate_hqc_keypair(variant: str = "hqc_256") -> Tuple[str, str]:
    """Generate HQC keypair and return as base64 strings."""
    hqc = HQCKEM(variant)
    public_key, private_key = hqc.generate_keypair()
    
    return (
        hqc.serialize_public_key(public_key),
        hqc.serialize_private_key(private_key)
    )

def hqc_encapsulate(public_key_str: str, variant: str = "hqc_256") -> Tuple[str, str]:
    """Encapsulate using HQC and return ciphertext and shared secret as base64."""
    hqc = HQCKEM(variant)
    public_key = hqc.deserialize_public_key(public_key_str)
    
    ciphertext, shared_secret = hqc.encapsulate(public_key)
    
    return (
        hqc.serialize_ciphertext(ciphertext),
        hqc.serialize_shared_secret(shared_secret)
    )

def hqc_decapsulate(private_key_str: str, ciphertext_str: str, 
                   variant: str = "hqc_256") -> str:
    """Decapsulate using HQC and return shared secret as base64."""
    hqc = HQCKEM(variant)
    private_key = hqc.deserialize_private_key(private_key_str)
    ciphertext = hqc.deserialize_ciphertext(ciphertext_str)
    
    shared_secret = hqc.decapsulate(private_key, ciphertext)
    
    return hqc.serialize_shared_secret(shared_secret)

def get_hqc_info(variant: str = "hqc_256") -> Dict[str, Any]:
    """Get information about HQC variant."""
    hqc = HQCKEM(variant)
    
    return {
        "variant": variant,
        "algorithm_name": hqc.get_algorithm_name(),
        "security_level": hqc.get_security_level(),
        "nist_level": hqc.get_nist_level(),
        "key_sizes": hqc.get_key_sizes(),
        "description": hqc.get_description(),
        "quantum_resistant": True,
        "algorithm_type": "Key Encapsulation Mechanism",
        "cryptographic_base": "Error-correcting codes",
        "standardization": "NIST 2025 selection as ML-KEM backup",
        "advantages": [
            "Diversity from lattice-based algorithms",
            "Code-based cryptography foundation",
            "Alternative to ML-KEM for backup security"
        ]
    }

def get_supported_hqc_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported HQC variants."""
    return {
        "hqc_128": {
            "name": "HQC-128",
            "security_level": 128,
            "nist_level": 1,
            "key_sizes": HQCVariant.HQC_128
        },
        "hqc_192": {
            "name": "HQC-192",
            "security_level": 192,
            "nist_level": 3,
            "key_sizes": HQCVariant.HQC_192
        },
        "hqc_256": {
            "name": "HQC-256",
            "security_level": 256,
            "nist_level": 5,
            "key_sizes": HQCVariant.HQC_256
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing HQC certified implementation...")
    
    # Test all variants
    for variant in ["hqc_128", "hqc_192", "hqc_256"]:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_hqc_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Encapsulate
        ciphertext, shared_secret1 = hqc_encapsulate(public_key, variant)
        print(f"Ciphertext: {ciphertext[:50]}...")
        print(f"Shared secret 1: {shared_secret1}")
        
        # Decapsulate
        shared_secret2 = hqc_decapsulate(private_key, ciphertext, variant)
        print(f"Shared secret 2: {shared_secret2}")
        
        # Verify shared secrets match
        print(f"Shared secrets match: {shared_secret1 == shared_secret2}")
        
        # Get algorithm info
        info = get_hqc_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"NIST level: {info['nist_level']}")
        print(f"Cryptographic base: {info['cryptographic_base']}")
    
    print("\n=== Supported Variants ===")
    variants = get_supported_hqc_variants()
    for name, info in variants.items():
        print(f"{name}: {info['name']} (Security: {info['security_level']} bits)")