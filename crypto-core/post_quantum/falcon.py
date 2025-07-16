"""
FALCON post-quantum digital signature implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
FALCON is expected to be standardized as FN-DSA in FIPS 206.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.sign import falcon_512, falcon_1024, falcon_padded_512, falcon_padded_1024

logger = logging.getLogger(__name__)

class FalconVariant:
    """FALCON variant configurations."""
    
    FALCON_512 = {
        "name": "FALCON-512",
        "module": falcon_512,
        "security_level": 112,
        "public_key_size": falcon_512.PUBLIC_KEY_SIZE,
        "private_key_size": falcon_512.SECRET_KEY_SIZE,
        "signature_size": falcon_512.SIGNATURE_SIZE,
        "nist_level": 1,
        "padded": False,
        "description": "Compact signatures, variable length"
    }
    
    FALCON_1024 = {
        "name": "FALCON-1024",
        "module": falcon_1024,
        "security_level": 256,
        "public_key_size": falcon_1024.PUBLIC_KEY_SIZE,
        "private_key_size": falcon_1024.SECRET_KEY_SIZE,
        "signature_size": falcon_1024.SIGNATURE_SIZE,
        "nist_level": 5,
        "padded": False,
        "description": "Compact signatures, variable length"
    }
    
    FALCON_PADDED_512 = {
        "name": "FALCON-PADDED-512",
        "module": falcon_padded_512,
        "security_level": 112,
        "public_key_size": falcon_padded_512.PUBLIC_KEY_SIZE,
        "private_key_size": falcon_padded_512.SECRET_KEY_SIZE,
        "signature_size": falcon_padded_512.SIGNATURE_SIZE,
        "nist_level": 1,
        "padded": True,
        "description": "Padded signatures, constant length"
    }
    
    FALCON_PADDED_1024 = {
        "name": "FALCON-PADDED-1024",
        "module": falcon_padded_1024,
        "security_level": 256,
        "public_key_size": falcon_padded_1024.PUBLIC_KEY_SIZE,
        "private_key_size": falcon_padded_1024.SECRET_KEY_SIZE,
        "signature_size": falcon_padded_1024.SIGNATURE_SIZE,
        "nist_level": 5,
        "padded": True,
        "description": "Padded signatures, constant length"
    }

class FalconSignature:
    """FALCON Digital Signature Algorithm using certified pqcrypto library."""
    
    def __init__(self, variant: str = "falcon_1024"):
        """Initialize FALCON with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified FALCON variant."""
        variant_map = {
            "falcon_512": FalconVariant.FALCON_512,
            "falcon_1024": FalconVariant.FALCON_1024,
            "falcon_padded_512": FalconVariant.FALCON_PADDED_512,
            "falcon_padded_1024": FalconVariant.FALCON_PADDED_1024,
            "falcon512": FalconVariant.FALCON_512,
            "falcon1024": FalconVariant.FALCON_1024,
            "falcon_padded512": FalconVariant.FALCON_PADDED_512,
            "falcon_padded1024": FalconVariant.FALCON_PADDED_1024
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported FALCON variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a FALCON keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"FALCON keypair generation failed: {e}")
            raise
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using the private key."""
        try:
            if len(private_key) != self.config["private_key_size"]:
                raise ValueError(f"Invalid private key size: {len(private_key)}, "
                               f"expected {self.config['private_key_size']}")
            
            signature = self.module.sign(private_key, message)
            
            logger.info(f"FALCON signature generated")
            logger.debug(f"Message: {len(message)} bytes, "
                        f"Signature: {len(signature)} bytes")
            
            return signature
            
        except Exception as e:
            logger.error(f"FALCON signing failed: {e}")
            raise
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using the public key."""
        try:
            if len(public_key) != self.config["public_key_size"]:
                raise ValueError(f"Invalid public key size: {len(public_key)}, "
                               f"expected {self.config['public_key_size']}")
            
            # Note: FALCON signatures can be variable length unless padded
            if self.config["padded"] and len(signature) != self.config["signature_size"]:
                raise ValueError(f"Invalid signature size: {len(signature)}, "
                               f"expected {self.config['signature_size']} (padded)")
            
            # pqcrypto verify throws exception on invalid signature
            self.module.verify(public_key, message, signature)
            
            logger.info(f"FALCON signature verification: valid")
            return True
            
        except Exception as e:
            logger.warning(f"FALCON signature verification: invalid - {e}")
            return False
    
    def get_key_sizes(self) -> Dict[str, int]:
        """Get key and signature sizes for current parameters."""
        return {
            "public_key_size": self.config["public_key_size"],
            "private_key_size": self.config["private_key_size"],
            "signature_size": self.config["signature_size"],
            "signature_variable_length": not self.config["padded"]
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
    
    def is_padded(self) -> bool:
        """Check if this is a padded variant."""
        return self.config["padded"]
    
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
def generate_falcon_keypair(variant: str = "falcon_1024") -> Tuple[str, str]:
    """Generate FALCON keypair and return as base64 strings."""
    falcon = FalconSignature(variant)
    public_key, private_key = falcon.generate_keypair()
    
    return (
        falcon.serialize_public_key(public_key),
        falcon.serialize_private_key(private_key)
    )

def falcon_sign(message: str, private_key_str: str, variant: str = "falcon_1024") -> str:
    """Sign message using FALCON and return signature as base64."""
    falcon = FalconSignature(variant)
    private_key = falcon.deserialize_private_key(private_key_str)
    
    signature = falcon.sign(message.encode('utf-8'), private_key)
    
    return falcon.serialize_signature(signature)

def falcon_verify(message: str, signature_str: str, public_key_str: str, 
                  variant: str = "falcon_1024") -> bool:
    """Verify signature using FALCON."""
    falcon = FalconSignature(variant)
    public_key = falcon.deserialize_public_key(public_key_str)
    signature = falcon.deserialize_signature(signature_str)
    
    return falcon.verify(message.encode('utf-8'), signature, public_key)

def get_falcon_info(variant: str = "falcon_1024") -> Dict[str, Any]:
    """Get information about FALCON variant."""
    falcon = FalconSignature(variant)
    
    return {
        "variant": variant,
        "algorithm_name": falcon.get_algorithm_name(),
        "security_level": falcon.get_security_level(),
        "nist_level": falcon.get_nist_level(),
        "key_sizes": falcon.get_key_sizes(),
        "is_padded": falcon.is_padded(),
        "description": falcon.get_description(),
        "quantum_resistant": True,
        "algorithm_type": "Digital Signature",
        "standardization": "Expected NIST FIPS 206 (FN-DSA)",
        "signature_characteristic": "Compact signatures, NTRU-lattice based"
    }

def get_supported_falcon_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported FALCON variants."""
    return {
        "falcon_512": {
            "name": "FALCON-512",
            "security_level": 112,
            "nist_level": 1,
            "padded": False,
            "key_sizes": FalconVariant.FALCON_512
        },
        "falcon_1024": {
            "name": "FALCON-1024",
            "security_level": 256,
            "nist_level": 5,
            "padded": False,
            "key_sizes": FalconVariant.FALCON_1024
        },
        "falcon_padded_512": {
            "name": "FALCON-PADDED-512",
            "security_level": 112,
            "nist_level": 1,
            "padded": True,
            "key_sizes": FalconVariant.FALCON_PADDED_512
        },
        "falcon_padded_1024": {
            "name": "FALCON-PADDED-1024",
            "security_level": 256,
            "nist_level": 5,
            "padded": True,
            "key_sizes": FalconVariant.FALCON_PADDED_1024
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing FALCON certified implementation...")
    
    # Test all variants
    for variant in ["falcon_512", "falcon_1024", "falcon_padded_512", "falcon_padded_1024"]:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_falcon_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Sign message
        message = "Hello, FALCON post-quantum world!"
        signature = falcon_sign(message, private_key, variant)
        print(f"Message: {message}")
        print(f"Signature: {signature[:50]}...")
        
        # Verify signature
        is_valid = falcon_verify(message, signature, public_key, variant)
        print(f"Signature valid: {is_valid}")
        
        # Test with wrong message
        wrong_message = "Hello, classical world!"
        is_valid_wrong = falcon_verify(wrong_message, signature, public_key, variant)
        print(f"Wrong message signature valid: {is_valid_wrong}")
        
        # Get algorithm info
        info = get_falcon_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"NIST level: {info['nist_level']}")
        print(f"Padded: {info['is_padded']}")
        print(f"Description: {info['description']}")
    
    print("\n=== Supported Variants ===")
    variants = get_supported_falcon_variants()
    for name, info in variants.items():
        padding = "Padded" if info["padded"] else "Variable"
        print(f"{name}: {info['name']} - Security: {info['security_level']} bits ({padding} signatures)")