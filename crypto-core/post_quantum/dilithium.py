"""
ML-DSA (Dilithium) post-quantum digital signature implementation.
This uses the certified pqcrypto library for NIST-approved algorithms.
"""
import base64
import logging
from typing import Tuple, Optional, Dict, Any

from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

logger = logging.getLogger(__name__)

class DilithiumVariant:
    """Dilithium/ML-DSA variant configurations."""
    
    DILITHIUM_2 = {
        "name": "ML-DSA-44",
        "module": ml_dsa_44,
        "security_level": 128,
        "public_key_size": ml_dsa_44.PUBLIC_KEY_SIZE,
        "private_key_size": ml_dsa_44.SECRET_KEY_SIZE,
        "signature_size": ml_dsa_44.SIGNATURE_SIZE,
        "nist_level": 2,
        "original_name": "Dilithium2"
    }
    
    DILITHIUM_3 = {
        "name": "ML-DSA-65",
        "module": ml_dsa_65,
        "security_level": 192,
        "public_key_size": ml_dsa_65.PUBLIC_KEY_SIZE,
        "private_key_size": ml_dsa_65.SECRET_KEY_SIZE,
        "signature_size": ml_dsa_65.SIGNATURE_SIZE,
        "nist_level": 3,
        "original_name": "Dilithium3"
    }
    
    DILITHIUM_5 = {
        "name": "ML-DSA-87",
        "module": ml_dsa_87,
        "security_level": 256,
        "public_key_size": ml_dsa_87.PUBLIC_KEY_SIZE,
        "private_key_size": ml_dsa_87.SECRET_KEY_SIZE,
        "signature_size": ml_dsa_87.SIGNATURE_SIZE,
        "nist_level": 5,
        "original_name": "Dilithium5"
    }

class DilithiumSignature:
    """ML-DSA (Dilithium) Digital Signature Algorithm using certified pqcrypto library."""
    
    def __init__(self, variant: str = "dilithium3"):
        """Initialize ML-DSA with specified variant."""
        self.variant = variant
        self.config = self._get_config(variant)
        self.module = self.config["module"]
        
        logger.info(f"Initialized {self.config['name']} with security level {self.config['security_level']}")
        
    def _get_config(self, variant: str) -> Dict[str, Any]:
        """Get configuration for specified ML-DSA variant."""
        variant_map = {
            "dilithium2": DilithiumVariant.DILITHIUM_2,
            "dilithium3": DilithiumVariant.DILITHIUM_3,
            "dilithium5": DilithiumVariant.DILITHIUM_5,
            "ml_dsa_44": DilithiumVariant.DILITHIUM_2,
            "ml_dsa_65": DilithiumVariant.DILITHIUM_3,
            "ml_dsa_87": DilithiumVariant.DILITHIUM_5
        }
        
        if variant not in variant_map:
            raise ValueError(f"Unsupported ML-DSA/Dilithium variant: {variant}. "
                           f"Supported variants: {list(variant_map.keys())}")
        
        return variant_map[variant]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate an ML-DSA keypair."""
        try:
            public_key, private_key = self.module.generate_keypair()
            
            logger.info(f"Generated {self.config['name']} keypair")
            logger.debug(f"Public key: {len(public_key)} bytes, "
                        f"Private key: {len(private_key)} bytes")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"ML-DSA keypair generation failed: {e}")
            raise
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message using the private key."""
        try:
            if len(private_key) != self.config["private_key_size"]:
                raise ValueError(f"Invalid private key size: {len(private_key)}, "
                               f"expected {self.config['private_key_size']}")
            
            signature = self.module.sign(private_key, message)
            
            logger.info(f"ML-DSA signature generated")
            logger.debug(f"Message: {len(message)} bytes, "
                        f"Signature: {len(signature)} bytes")
            
            return signature
            
        except Exception as e:
            logger.error(f"ML-DSA signing failed: {e}")
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
            
            logger.info(f"ML-DSA signature verification: valid")
            return True
            
        except Exception as e:
            logger.warning(f"ML-DSA signature verification: invalid - {e}")
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
        """Get the official algorithm name."""
        return self.config["name"]
    
    def get_original_name(self) -> str:
        """Get the original algorithm name."""
        return self.config["original_name"]
    
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

# Convenience functions for backward compatibility
def generate_dilithium_keypair(variant: str = "dilithium3") -> Tuple[str, str]:
    """Generate ML-DSA keypair and return as base64 strings."""
    dilithium = DilithiumSignature(variant)
    public_key, private_key = dilithium.generate_keypair()
    
    return (
        dilithium.serialize_public_key(public_key),
        dilithium.serialize_private_key(private_key)
    )

def dilithium_sign(message: str, private_key_str: str, variant: str = "dilithium3") -> str:
    """Sign message using ML-DSA and return signature as base64."""
    dilithium = DilithiumSignature(variant)
    private_key = dilithium.deserialize_private_key(private_key_str)
    
    signature = dilithium.sign(message.encode('utf-8'), private_key)
    
    return dilithium.serialize_signature(signature)

def dilithium_verify(message: str, signature_str: str, public_key_str: str, 
                    variant: str = "dilithium3") -> bool:
    """Verify signature using ML-DSA."""
    dilithium = DilithiumSignature(variant)
    public_key = dilithium.deserialize_public_key(public_key_str)
    signature = dilithium.deserialize_signature(signature_str)
    
    return dilithium.verify(message.encode('utf-8'), signature, public_key)

def get_dilithium_info(variant: str = "dilithium3") -> Dict[str, Any]:
    """Get information about ML-DSA variant."""
    dilithium = DilithiumSignature(variant)
    
    return {
        "variant": variant,
        "algorithm_name": dilithium.get_algorithm_name(),
        "original_name": dilithium.get_original_name(),
        "security_level": dilithium.get_security_level(),
        "nist_level": dilithium.get_nist_level(),
        "key_sizes": dilithium.get_key_sizes(),
        "quantum_resistant": True,
        "algorithm_type": "Digital Signature",
        "standardization": "NIST FIPS 204",
        "description": "NIST-standardized post-quantum digital signature algorithm"
    }

def get_supported_dilithium_variants() -> Dict[str, Dict[str, Any]]:
    """Get all supported ML-DSA variants."""
    return {
        "dilithium2": {
            "name": "ML-DSA-44",
            "original_name": "Dilithium2",
            "security_level": 128,
            "nist_level": 2,
            "key_sizes": DilithiumVariant.DILITHIUM_2
        },
        "dilithium3": {
            "name": "ML-DSA-65",
            "original_name": "Dilithium3",
            "security_level": 192,
            "nist_level": 3,
            "key_sizes": DilithiumVariant.DILITHIUM_3
        },
        "dilithium5": {
            "name": "ML-DSA-87",
            "original_name": "Dilithium5",
            "security_level": 256,
            "nist_level": 5,
            "key_sizes": DilithiumVariant.DILITHIUM_5
        }
    }

# Example usage and testing
if __name__ == "__main__":
    print("Testing ML-DSA (Dilithium) certified implementation...")
    
    # Test all variants
    for variant in ["dilithium2", "dilithium3", "dilithium5"]:
        print(f"\n=== Testing {variant} ===")
        
        # Generate keypair
        public_key, private_key = generate_dilithium_keypair(variant)
        print(f"Public key: {public_key[:50]}...")
        print(f"Private key: {private_key[:50]}...")
        
        # Sign message
        message = "Hello, post-quantum world!"
        signature = dilithium_sign(message, private_key, variant)
        print(f"Message: {message}")
        print(f"Signature: {signature[:50]}...")
        
        # Verify signature
        is_valid = dilithium_verify(message, signature, public_key, variant)
        print(f"Signature valid: {is_valid}")
        
        # Test with wrong message
        wrong_message = "Hello, classical world!"
        is_valid_wrong = dilithium_verify(wrong_message, signature, public_key, variant)
        print(f"Wrong message signature valid: {is_valid_wrong}")
        
        # Get algorithm info
        info = get_dilithium_info(variant)
        print(f"Algorithm: {info['algorithm_name']}")
        print(f"Original name: {info['original_name']}")
        print(f"Security level: {info['security_level']} bits")
        print(f"NIST level: {info['nist_level']}")
    
    print("\n=== Supported Variants ===")
    variants = get_supported_dilithium_variants()
    for name, info in variants.items():
        print(f"{name}: {info['name']} ({info['original_name']}) - Security: {info['security_level']} bits")