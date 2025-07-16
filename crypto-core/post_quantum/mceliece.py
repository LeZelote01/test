"""
Classic McEliece post-quantum key encapsulation mechanism implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
Classic McEliece is a code-based cryptosystem using Goppa codes.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.kem import (
    mceliece348864, mceliece348864f,
    mceliece460896, mceliece460896f,
    mceliece6688128, mceliece6688128f,
    mceliece6960119, mceliece6960119f,
    mceliece8192128, mceliece8192128f
)

logger = logging.getLogger(__name__)

class McElieceVariant:
    """Classic McEliece variant configurations."""
    
    MCELIECE_348864 = {
        "name": "Classic McEliece 348864",
        "module": mceliece348864,
        "security_level": 128,
        "nist_level": 1,
        "fast_variant": False,
        "description": "Conservative parameter set with Goppa codes"
    }
    
    MCELIECE_348864F = {
        "name": "Classic McEliece 348864f",
        "module": mceliece348864f,
        "security_level": 128,
        "nist_level": 1,
        "fast_variant": True,
        "description": "Fast parameter set with Goppa codes"
    }
    
    MCELIECE_460896 = {
        "name": "Classic McEliece 460896",
        "module": mceliece460896,
        "security_level": 128,
        "nist_level": 1,
        "fast_variant": False,
        "description": "Conservative parameter set with Goppa codes"
    }
    
    MCELIECE_460896F = {
        "name": "Classic McEliece 460896f",
        "module": mceliece460896f,
        "security_level": 128,
        "nist_level": 1,
        "fast_variant": True,
        "description": "Fast parameter set with Goppa codes"
    }
    
    MCELIECE_6688128 = {
        "name": "Classic McEliece 6688128",
        "module": mceliece6688128,
        "security_level": 192,
        "nist_level": 3,
        "fast_variant": False,
        "description": "Conservative parameter set with Goppa codes"
    }
    
    MCELIECE_6688128F = {
        "name": "Classic McEliece 6688128f",
        "module": mceliece6688128f,
        "security_level": 192,
        "nist_level": 3,
        "fast_variant": True,
        "description": "Fast parameter set with Goppa codes"
    }
    
    MCELIECE_6960119 = {
        "name": "Classic McEliece 6960119",
        "module": mceliece6960119,
        "security_level": 192,
        "nist_level": 3,
        "fast_variant": False,
        "description": "Conservative parameter set with Goppa codes"
    }
    
    MCELIECE_6960119F = {
        "name": "Classic McEliece 6960119f",
        "module": mceliece6960119f,
        "security_level": 192,
        "nist_level": 3,
        "fast_variant": True,
        "description": "Fast parameter set with Goppa codes"
    }
    
    MCELIECE_8192128 = {
        "name": "Classic McEliece 8192128",
        "module": mceliece8192128,
        "security_level": 256,
        "nist_level": 5,
        "fast_variant": False,
        "description": "Conservative parameter set with Goppa codes"
    }
    
    MCELIECE_8192128F = {
        "name": "Classic McEliece 8192128f",
        "module": mceliece8192128f,
        "security_level": 256,
        "nist_level": 5,
        "fast_variant": True,
        "description": "Fast parameter set with Goppa codes"
    }

class McElieceKEM:
    """Classic McEliece Key Encapsulation Mechanism using certified pqcrypto library."""
    
    def __init__(self, variant: str = "mceliece6688128"):
        """Initialize Classic McEliece with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        # Get actual sizes from module
        self.config.update({
            "public_key_size": self.module.PUBLIC_KEY_SIZE,
            "private_key_size": self.module.SECRET_KEY_SIZE,
            "ciphertext_size": self.module.CIPHERTEXT_SIZE,
            "shared_secret_size": self.module.PLAINTEXT_SIZE
        })
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified Classic McEliece variant."""
        variant_map = {
            "mceliece348864": McElieceVariant.MCELIECE_348864,
            "mceliece348864f": McElieceVariant.MCELIECE_348864F,
            "mceliece460896": McElieceVariant.MCELIECE_460896,
            "mceliece460896f": McElieceVariant.MCELIECE_460896F,
            "mceliece6688128": McElieceVariant.MCELIECE_6688128,
            "mceliece6688128f": McElieceVariant.MCELIECE_6688128F,
            "mceliece6960119": McElieceVariant.MCELIECE_6960119,
            "mceliece6960119f": McElieceVariant.MCELIECE_6960119F,
            "mceliece8192128": McElieceVariant.MCELIECE_8192128,
            "mceliece8192128f": McElieceVariant.MCELIECE_8192128F
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported Classic McEliece variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant].copy()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a Classic McEliece keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"Classic McEliece keypair generation failed: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the public key."""
        try:
            if len(public_key) != self.config["public_key_size"]:
                raise ValueError(f"Invalid public key size: {len(public_key)}, "
                               f"expected {self.config['public_key_size']}")
            
            ciphertext, shared_secret = self.module.encrypt(public_key)
            
            logger.info(f"Classic McEliece encapsulation completed")
            logger.debug(f"Ciphertext: {len(ciphertext)} bytes, "
                        f"Shared secret: {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
            
        except Exception as e:
            logger.error(f"Classic McEliece encapsulation failed: {e}")
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
            
            logger.info(f"Classic McEliece decapsulation completed")
            logger.debug(f"Shared secret: {len(shared_secret)} bytes")
            
            return shared_secret
            
        except Exception as e:
            logger.error(f"Classic McEliece decapsulation failed: {e}")
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
    
    def is_fast_variant(self) -> bool:
        """Check if this is a fast variant."""
        return self.config["fast_variant"]
    
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
def generate_mceliece_keypair(variant: str = "mceliece6688128") -> Tuple[str, str]:
    """Generate Classic McEliece keypair and return as base64 strings."""
    mceliece = McElieceKEM(variant)
    public_key, private_key = mceliece.generate_keypair()
    
    return (
        mceliece.serialize_public_key(public_key),
        mceliece.serialize_private_key(private_key)
    )

def mceliece_encapsulate(public_key_str: str, variant: str = "mceliece6688128") -> Tuple[str, str]:
    """Encapsulate using Classic McEliece and return ciphertext and shared secret as base64."""
    mceliece = McElieceKEM(variant)
    public_key = mceliece.deserialize_public_key(public_key_str)
    
    ciphertext, shared_secret = mceliece.encapsulate(public_key)
    
    return (
        mceliece.serialize_ciphertext(ciphertext),
        mceliece.serialize_shared_secret(shared_secret)
    )

def mceliece_decapsulate(private_key_str: str, ciphertext_str: str, 
                        variant: str = "mceliece6688128") -> str:
    """Decapsulate using Classic McEliece and return shared secret as base64."""
    mceliece = McElieceKEM(variant)
    private_key = mceliece.deserialize_private_key(private_key_str)
    ciphertext = mceliece.deserialize_ciphertext(ciphertext_str)
    
    shared_secret = mceliece.decapsulate(private_key, ciphertext)
    
    return mceliece.serialize_shared_secret(shared_secret)

def get_mceliece_info(variant: str = "mceliece6688128") -> Dict[str, Any]:
    """Get information about Classic McEliece variant."""
    mceliece = McElieceKEM(variant)
    
    return {
        "variant": variant,
        "algorithm_name": mceliece.get_algorithm_name(),
        "security_level": mceliece.get_security_level(),
        "nist_level": mceliece.get_nist_level(),
        "key_sizes": mceliece.get_key_sizes(),
        "is_fast_variant": mceliece.is_fast_variant(),
        "description": mceliece.get_description(),
        "quantum_resistant": True,
        "algorithm_type": "Key Encapsulation Mechanism",
        "cryptographic_base": "Error-correcting codes (Goppa codes)",
        "standardization": "NIST Round 4 alternate candidate",
        "characteristics": [
            "Conservative security assumptions",
            "Large key sizes but well-understood",
            "Code-based cryptography",
            "Mature mathematical foundation"
        ]
    }

def get_supported_mceliece_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported Classic McEliece variants."""
    return {
        "mceliece348864": {
            "name": "Classic McEliece 348864",
            "security_level": 128,
            "nist_level": 1,
            "fast_variant": False
        },
        "mceliece348864f": {
            "name": "Classic McEliece 348864f",
            "security_level": 128,
            "nist_level": 1,
            "fast_variant": True
        },
        "mceliece460896": {
            "name": "Classic McEliece 460896",
            "security_level": 128,
            "nist_level": 1,
            "fast_variant": False
        },
        "mceliece460896f": {
            "name": "Classic McEliece 460896f",
            "security_level": 128,
            "nist_level": 1,
            "fast_variant": True
        },
        "mceliece6688128": {
            "name": "Classic McEliece 6688128",
            "security_level": 192,
            "nist_level": 3,
            "fast_variant": False
        },
        "mceliece6688128f": {
            "name": "Classic McEliece 6688128f",
            "security_level": 192,
            "nist_level": 3,
            "fast_variant": True
        },
        "mceliece6960119": {
            "name": "Classic McEliece 6960119",
            "security_level": 192,
            "nist_level": 3,
            "fast_variant": False
        },
        "mceliece6960119f": {
            "name": "Classic McEliece 6960119f",
            "security_level": 192,
            "nist_level": 3,
            "fast_variant": True
        },
        "mceliece8192128": {
            "name": "Classic McEliece 8192128",
            "security_level": 256,
            "nist_level": 5,
            "fast_variant": False
        },
        "mceliece8192128f": {
            "name": "Classic McEliece 8192128f",
            "security_level": 256,
            "nist_level": 5,
            "fast_variant": True
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing Classic McEliece certified implementation...")
    
    # Test key variants (smaller ones for faster testing)
    test_variants = [
        "mceliece348864",
        "mceliece348864f",
        "mceliece460896",
        "mceliece460896f"
    ]
    
    for variant in test_variants:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_mceliece_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Encapsulate
        ciphertext, shared_secret1 = mceliece_encapsulate(public_key, variant)
        print(f"Ciphertext: {ciphertext[:50]}...")
        print(f"Shared secret 1: {shared_secret1}")
        
        # Decapsulate
        shared_secret2 = mceliece_decapsulate(private_key, ciphertext, variant)
        print(f"Shared secret 2: {shared_secret2}")
        
        # Verify shared secrets match
        print(f"Shared secrets match: {shared_secret1 == shared_secret2}")
        
        # Get algorithm info
        info = get_mceliece_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"NIST level: {info['nist_level']}")
        print(f"Fast variant: {info['is_fast_variant']}")
        print(f"Cryptographic base: {info['cryptographic_base']}")
    
    print("\n=== Supported Variants Summary ===")
    variants = get_supported_mceliece_variants()
    for name, info in variants.items():
        variant_type = "Fast" if info["fast_variant"] else "Conservative"
        print(f"{name}: {info['name']} - {info['security_level']} bits ({variant_type})")