"""
SPHINCS+ post-quantum digital signature implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
SPHINCS+ is standardized as SLH-DSA in FIPS 205.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.sign import (
    sphincs_sha2_128f_simple, sphincs_sha2_128s_simple,
    sphincs_sha2_192f_simple, sphincs_sha2_192s_simple,
    sphincs_sha2_256f_simple, sphincs_sha2_256s_simple,
    sphincs_shake_128f_simple, sphincs_shake_128s_simple,
    sphincs_shake_192f_simple, sphincs_shake_192s_simple,
    sphincs_shake_256f_simple, sphincs_shake_256s_simple
)

logger = logging.getLogger(__name__)

class SphincsVariant:
    """SPHINCS+ variant configurations."""
    
    # SHA2 variants
    SPHINCS_SHA2_128F = {
        "name": "SPHINCS+-SHA2-128f",
        "module": sphincs_sha2_128f_simple,
        "security_level": 128,
        "hash_function": "SHA2",
        "variant_type": "f",  # fast
        "nist_level": 1,
        "description": "Fast variant with SHA2 hash function"
    }
    
    SPHINCS_SHA2_128S = {
        "name": "SPHINCS+-SHA2-128s",
        "module": sphincs_sha2_128s_simple,
        "security_level": 128,
        "hash_function": "SHA2",
        "variant_type": "s",  # small
        "nist_level": 1,
        "description": "Small variant with SHA2 hash function"
    }
    
    SPHINCS_SHA2_192F = {
        "name": "SPHINCS+-SHA2-192f",
        "module": sphincs_sha2_192f_simple,
        "security_level": 192,
        "hash_function": "SHA2",
        "variant_type": "f",
        "nist_level": 3,
        "description": "Fast variant with SHA2 hash function"
    }
    
    SPHINCS_SHA2_192S = {
        "name": "SPHINCS+-SHA2-192s",
        "module": sphincs_sha2_192s_simple,
        "security_level": 192,
        "hash_function": "SHA2",
        "variant_type": "s",
        "nist_level": 3,
        "description": "Small variant with SHA2 hash function"
    }
    
    SPHINCS_SHA2_256F = {
        "name": "SPHINCS+-SHA2-256f",
        "module": sphincs_sha2_256f_simple,
        "security_level": 256,
        "hash_function": "SHA2",
        "variant_type": "f",
        "nist_level": 5,
        "description": "Fast variant with SHA2 hash function"
    }
    
    SPHINCS_SHA2_256S = {
        "name": "SPHINCS+-SHA2-256s",
        "module": sphincs_sha2_256s_simple,
        "security_level": 256,
        "hash_function": "SHA2",
        "variant_type": "s",
        "nist_level": 5,
        "description": "Small variant with SHA2 hash function"
    }
    
    # SHAKE variants
    SPHINCS_SHAKE_128F = {
        "name": "SPHINCS+-SHAKE-128f",
        "module": sphincs_shake_128f_simple,
        "security_level": 128,
        "hash_function": "SHAKE",
        "variant_type": "f",
        "nist_level": 1,
        "description": "Fast variant with SHAKE hash function"
    }
    
    SPHINCS_SHAKE_128S = {
        "name": "SPHINCS+-SHAKE-128s",
        "module": sphincs_shake_128s_simple,
        "security_level": 128,
        "hash_function": "SHAKE",
        "variant_type": "s",
        "nist_level": 1,
        "description": "Small variant with SHAKE hash function"
    }
    
    SPHINCS_SHAKE_192F = {
        "name": "SPHINCS+-SHAKE-192f",
        "module": sphincs_shake_192f_simple,
        "security_level": 192,
        "hash_function": "SHAKE",
        "variant_type": "f",
        "nist_level": 3,
        "description": "Fast variant with SHAKE hash function"
    }
    
    SPHINCS_SHAKE_192S = {
        "name": "SPHINCS+-SHAKE-192s",
        "module": sphincs_shake_192s_simple,
        "security_level": 192,
        "hash_function": "SHAKE",
        "variant_type": "s",
        "nist_level": 3,
        "description": "Small variant with SHAKE hash function"
    }
    
    SPHINCS_SHAKE_256F = {
        "name": "SPHINCS+-SHAKE-256f",
        "module": sphincs_shake_256f_simple,
        "security_level": 256,
        "hash_function": "SHAKE",
        "variant_type": "f",
        "nist_level": 5,
        "description": "Fast variant with SHAKE hash function"
    }
    
    SPHINCS_SHAKE_256S = {
        "name": "SPHINCS+-SHAKE-256s",
        "module": sphincs_shake_256s_simple,
        "security_level": 256,
        "hash_function": "SHAKE",
        "variant_type": "s",
        "nist_level": 5,
        "description": "Small variant with SHAKE hash function"
    }

class SphincsSignature:
    """SPHINCS+ Digital Signature Algorithm using certified pqcrypto library."""
    
    def __init__(self, variant: str = "sphincs_sha2_256f_simple"):
        """Initialize SPHINCS+ with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        # Get actual sizes from module
        self.config.update({
            "public_key_size": self.module.PUBLIC_KEY_SIZE,
            "private_key_size": self.module.SECRET_KEY_SIZE,
            "signature_size": self.module.SIGNATURE_SIZE
        })
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified SPHINCS+ variant."""
        variant_map = {
            # SHA2 variants
            "sphincs_sha2_128f_simple": SphincsVariant.SPHINCS_SHA2_128F,
            "sphincs_sha2_128s_simple": SphincsVariant.SPHINCS_SHA2_128S,
            "sphincs_sha2_192f_simple": SphincsVariant.SPHINCS_SHA2_192F,
            "sphincs_sha2_192s_simple": SphincsVariant.SPHINCS_SHA2_192S,
            "sphincs_sha2_256f_simple": SphincsVariant.SPHINCS_SHA2_256F,
            "sphincs_sha2_256s_simple": SphincsVariant.SPHINCS_SHA2_256S,
            
            # SHAKE variants
            "sphincs_shake_128f_simple": SphincsVariant.SPHINCS_SHAKE_128F,
            "sphincs_shake_128s_simple": SphincsVariant.SPHINCS_SHAKE_128S,
            "sphincs_shake_192f_simple": SphincsVariant.SPHINCS_SHAKE_192F,
            "sphincs_shake_192s_simple": SphincsVariant.SPHINCS_SHAKE_192S,
            "sphincs_shake_256f_simple": SphincsVariant.SPHINCS_SHAKE_256F,
            "sphincs_shake_256s_simple": SphincsVariant.SPHINCS_SHAKE_256S,
            
            # Shorter aliases
            "sphincs_sha2_128f": SphincsVariant.SPHINCS_SHA2_128F,
            "sphincs_sha2_128s": SphincsVariant.SPHINCS_SHA2_128S,
            "sphincs_sha2_192f": SphincsVariant.SPHINCS_SHA2_192F,
            "sphincs_sha2_192s": SphincsVariant.SPHINCS_SHA2_192S,
            "sphincs_sha2_256f": SphincsVariant.SPHINCS_SHA2_256F,
            "sphincs_sha2_256s": SphincsVariant.SPHINCS_SHA2_256S,
            "sphincs_shake_128f": SphincsVariant.SPHINCS_SHAKE_128F,
            "sphincs_shake_128s": SphincsVariant.SPHINCS_SHAKE_128S,
            "sphincs_shake_192f": SphincsVariant.SPHINCS_SHAKE_192F,
            "sphincs_shake_192s": SphincsVariant.SPHINCS_SHAKE_192S,
            "sphincs_shake_256f": SphincsVariant.SPHINCS_SHAKE_256F,
            "sphincs_shake_256s": SphincsVariant.SPHINCS_SHAKE_256S
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported SPHINCS+ variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant].copy()
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a SPHINCS+ keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"SPHINCS+ keypair generation failed: {e}")
            raise
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using the private key."""
        try:
            if len(private_key) != self.config["private_key_size"]:
                raise ValueError(f"Invalid private key size: {len(private_key)}, "
                               f"expected {self.config['private_key_size']}")
            
            signature = self.module.sign(private_key, message)
            
            logger.info(f"SPHINCS+ signature generated")
            logger.debug(f"Message: {len(message)} bytes, "
                        f"Signature: {len(signature)} bytes")
            
            return signature
            
        except Exception as e:
            logger.error(f"SPHINCS+ signing failed: {e}")
            raise
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using the public key."""
        try:
            if len(public_key) != self.config["public_key_size"]:
                raise ValueError(f"Invalid public key size: {len(public_key)}, "
                               f"expected {self.config['public_key_size']}")
            
            if len(signature) != self.config["signature_size"]:
                raise ValueError(f"Invalid signature size: {len(signature)}, "
                               f"expected {self.config['signature_size']}")
            
            # pqcrypto verify throws exception on invalid signature
            self.module.verify(public_key, message, signature)
            
            logger.info(f"SPHINCS+ signature verification: valid")
            return True
            
        except Exception as e:
            logger.warning(f"SPHINCS+ signature verification: invalid - {e}")
            return False
    
    def get_key_sizes(self) -> Dict[str, int]:
        """Get key and signature sizes for current parameters."""
        return {
            "public_key_size": self.config["public_key_size"],
            "private_key_size": self.config["private_key_size"],
            "signature_size": self.config["signature_size"]
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
    
    def get_hash_function(self) -> str:
        """Get the hash function used."""
        return self.config["hash_function"]
    
    def get_variant_type(self) -> str:
        """Get the variant type (f for fast, s for small)."""
        return self.config["variant_type"]
    
    def is_fast_variant(self) -> bool:
        """Check if this is a fast variant."""
        return self.config["variant_type"] == "f"
    
    def is_small_variant(self) -> bool:
        """Check if this is a small variant."""
        return self.config["variant_type"] == "s"
    
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
    
    def serialize_signature(self, signature: bytes) -> str:
        """Serialize signature to base64 string."""
        return base64.b64encode(signature).decode('utf-8')
    
    def deserialize_signature(self, signature_str: str) -> bytes:
        """Deserialize signature from base64 string."""
        try:
            return base64.b64decode(signature_str.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid signature format: {e}")

# Convenience functions
def generate_sphincs_keypair(variant: str = "sphincs_sha2_256f_simple") -> Tuple[str, str]:
    """Generate SPHINCS+ keypair and return as base64 strings."""
    sphincs = SphincsSignature(variant)
    public_key, private_key = sphincs.generate_keypair()
    
    return (
        sphincs.serialize_public_key(public_key),
        sphincs.serialize_private_key(private_key)
    )

def sphincs_sign(message: str, private_key_str: str, variant: str = "sphincs_sha2_256f_simple") -> str:
    """Sign message using SPHINCS+ and return signature as base64."""
    sphincs = SphincsSignature(variant)
    private_key = sphincs.deserialize_private_key(private_key_str)
    
    signature = sphincs.sign(message.encode('utf-8'), private_key)
    
    return sphincs.serialize_signature(signature)

def sphincs_verify(message: str, signature_str: str, public_key_str: str, 
                   variant: str = "sphincs_sha2_256f_simple") -> bool:
    """Verify signature using SPHINCS+."""
    sphincs = SphincsSignature(variant)
    public_key = sphincs.deserialize_public_key(public_key_str)
    signature = sphincs.deserialize_signature(signature_str)
    
    return sphincs.verify(message.encode('utf-8'), signature, public_key)

def get_sphincs_info(variant: str = "sphincs_sha2_256f_simple") -> Dict[str, Any]:
    """Get information about SPHINCS+ variant."""
    sphincs = SphincsSignature(variant)
    
    return {
        "variant": variant,
        "algorithm_name": sphincs.get_algorithm_name(),
        "security_level": sphincs.get_security_level(),
        "nist_level": sphincs.get_nist_level(),
        "hash_function": sphincs.get_hash_function(),
        "variant_type": sphincs.get_variant_type(),
        "is_fast_variant": sphincs.is_fast_variant(),
        "is_small_variant": sphincs.is_small_variant(),
        "key_sizes": sphincs.get_key_sizes(),
        "description": sphincs.get_description(),
        "quantum_resistant": True,
        "algorithm_type": "Digital Signature",
        "standardization": "NIST FIPS 205 (SLH-DSA)",
        "signature_characteristic": "Stateless hash-based signatures"
    }

def get_supported_sphincs_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported SPHINCS+ variants."""
    return {
        # SHA2 variants
        "sphincs_sha2_128f_simple": {
            "name": "SPHINCS+-SHA2-128f",
            "security_level": 128,
            "hash_function": "SHA2",
            "variant_type": "fast",
            "nist_level": 1
        },
        "sphincs_sha2_128s_simple": {
            "name": "SPHINCS+-SHA2-128s",
            "security_level": 128,
            "hash_function": "SHA2",
            "variant_type": "small",
            "nist_level": 1
        },
        "sphincs_sha2_192f_simple": {
            "name": "SPHINCS+-SHA2-192f",
            "security_level": 192,
            "hash_function": "SHA2",
            "variant_type": "fast",
            "nist_level": 3
        },
        "sphincs_sha2_192s_simple": {
            "name": "SPHINCS+-SHA2-192s",
            "security_level": 192,
            "hash_function": "SHA2",
            "variant_type": "small",
            "nist_level": 3
        },
        "sphincs_sha2_256f_simple": {
            "name": "SPHINCS+-SHA2-256f",
            "security_level": 256,
            "hash_function": "SHA2",
            "variant_type": "fast",
            "nist_level": 5
        },
        "sphincs_sha2_256s_simple": {
            "name": "SPHINCS+-SHA2-256s",
            "security_level": 256,
            "hash_function": "SHA2",
            "variant_type": "small",
            "nist_level": 5
        },
        # SHAKE variants
        "sphincs_shake_128f_simple": {
            "name": "SPHINCS+-SHAKE-128f",
            "security_level": 128,
            "hash_function": "SHAKE",
            "variant_type": "fast",
            "nist_level": 1
        },
        "sphincs_shake_128s_simple": {
            "name": "SPHINCS+-SHAKE-128s",
            "security_level": 128,
            "hash_function": "SHAKE",
            "variant_type": "small",
            "nist_level": 1
        },
        "sphincs_shake_192f_simple": {
            "name": "SPHINCS+-SHAKE-192f",
            "security_level": 192,
            "hash_function": "SHAKE",
            "variant_type": "fast",
            "nist_level": 3
        },
        "sphincs_shake_192s_simple": {
            "name": "SPHINCS+-SHAKE-192s",
            "security_level": 192,
            "hash_function": "SHAKE",
            "variant_type": "small",
            "nist_level": 3
        },
        "sphincs_shake_256f_simple": {
            "name": "SPHINCS+-SHAKE-256f",
            "security_level": 256,
            "hash_function": "SHAKE",
            "variant_type": "fast",
            "nist_level": 5
        },
        "sphincs_shake_256s_simple": {
            "name": "SPHINCS+-SHAKE-256s",
            "security_level": 256,
            "hash_function": "SHAKE",
            "variant_type": "small",
            "nist_level": 5
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing SPHINCS+ certified implementation...")
    
    # Test key variants
    test_variants = [
        "sphincs_sha2_128f_simple",
        "sphincs_sha2_256f_simple",
        "sphincs_shake_128f_simple",
        "sphincs_shake_256f_simple"
    ]
    
    for variant in test_variants:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_sphincs_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Sign message
        message = "Hello, SPHINCS+ post-quantum world!"
        signature = sphincs_sign(message, private_key, variant)
        print(f"Message: {message}")
        print(f"Signature: {signature[:50]}...")
        
        # Verify signature
        is_valid = sphincs_verify(message, signature, public_key, variant)
        print(f"Signature valid: {is_valid}")
        
        # Test with wrong message
        wrong_message = "Hello, classical world!"
        is_valid_wrong = sphincs_verify(wrong_message, signature, public_key, variant)
        print(f"Wrong message signature valid: {is_valid_wrong}")
        
        # Get algorithm info
        info = get_sphincs_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"Hash function: {info['hash_function']}")
        print(f"Variant type: {info['variant_type']}")
    
    print("\n=== Supported Variants Summary ===")
    variants = get_supported_sphincs_variants()
    for name, info in variants.items():
        print(f"{name}: {info['name']} - {info['security_level']} bits ({info['hash_function']}, {info['variant_type']})")