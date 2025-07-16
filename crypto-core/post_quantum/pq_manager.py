"""
Post-Quantum Cryptography Manager for QuantumGate.
Provides unified interface for all NIST-certified post-quantum algorithms.
Updated to use certified pqcrypto library implementations.
"""
import logging
from typing import Dict, Any, Tuple, Optional, List, Union
from enum import Enum
import time
import base64

# Import certified algorithm implementations
from .kyber import KyberKEM, generate_kyber_keypair, kyber_encapsulate, kyber_decapsulate, get_kyber_info
from .dilithium import DilithiumSignature, generate_dilithium_keypair, dilithium_sign, dilithium_verify, get_dilithium_info
from .falcon import FalconSignature, generate_falcon_keypair, falcon_sign, falcon_verify, get_falcon_info
from .sphincs import SphincsSignature, generate_sphincs_keypair, sphincs_sign, sphincs_verify, get_sphincs_info
from .hqc import HQCKEM, generate_hqc_keypair, hqc_encapsulate, hqc_decapsulate, get_hqc_info
from .mceliece import McElieceKEM, generate_mceliece_keypair, mceliece_encapsulate, mceliece_decapsulate, get_mceliece_info

logger = logging.getLogger(__name__)

class PQAlgorithm(str, Enum):
    """Post-quantum algorithms supported."""
    # Key Encapsulation Mechanisms (KEMs)
    ML_KEM = "ml_kem"          # ML-KEM (Kyber) - NIST standardized
    KYBER = "kyber"            # Alias for ML-KEM
    HQC = "hqc"                # HQC - NIST 2025 backup to ML-KEM
    MCELIECE = "mceliece"      # Classic McEliece - NIST Round 4 alternate
    
    # Digital Signature Algorithms (DSAs)
    ML_DSA = "ml_dsa"          # ML-DSA (Dilithium) - NIST standardized
    DILITHIUM = "dilithium"    # Alias for ML-DSA
    FALCON = "falcon"          # FALCON - Expected NIST FIPS 206
    SPHINCS = "sphincs"        # SPHINCS+ (SLH-DSA) - NIST standardized
    
    # Hybrid combinations
    HYBRID = "hybrid"          # Hybrid classical + post-quantum

class PQVariant(str, Enum):
    """Post-quantum algorithm variants."""
    # ML-KEM (Kyber) variants
    KYBER_512 = "kyber512"
    KYBER_768 = "kyber768"
    KYBER_1024 = "kyber1024"
    ML_KEM_512 = "ml_kem_512"
    ML_KEM_768 = "ml_kem_768"
    ML_KEM_1024 = "ml_kem_1024"
    
    # ML-DSA (Dilithium) variants
    DILITHIUM_2 = "dilithium2"
    DILITHIUM_3 = "dilithium3"
    DILITHIUM_5 = "dilithium5"
    ML_DSA_44 = "ml_dsa_44"
    ML_DSA_65 = "ml_dsa_65"
    ML_DSA_87 = "ml_dsa_87"
    
    # FALCON variants
    FALCON_512 = "falcon_512"
    FALCON_1024 = "falcon_1024"
    FALCON_PADDED_512 = "falcon_padded_512"
    FALCON_PADDED_1024 = "falcon_padded_1024"
    
    # SPHINCS+ variants
    SPHINCS_SHA2_128F = "sphincs_sha2_128f_simple"
    SPHINCS_SHA2_128S = "sphincs_sha2_128s_simple"
    SPHINCS_SHA2_192F = "sphincs_sha2_192f_simple"
    SPHINCS_SHA2_192S = "sphincs_sha2_192s_simple"
    SPHINCS_SHA2_256F = "sphincs_sha2_256f_simple"
    SPHINCS_SHA2_256S = "sphincs_sha2_256s_simple"
    SPHINCS_SHAKE_128F = "sphincs_shake_128f_simple"
    SPHINCS_SHAKE_128S = "sphincs_shake_128s_simple"
    SPHINCS_SHAKE_192F = "sphincs_shake_192f_simple"
    SPHINCS_SHAKE_192S = "sphincs_shake_192s_simple"
    SPHINCS_SHAKE_256F = "sphincs_shake_256f_simple"
    SPHINCS_SHAKE_256S = "sphincs_shake_256s_simple"
    
    # HQC variants
    HQC_128 = "hqc_128"
    HQC_192 = "hqc_192"
    HQC_256 = "hqc_256"
    
    # Classic McEliece variants
    MCELIECE_348864 = "mceliece348864"
    MCELIECE_348864F = "mceliece348864f"
    MCELIECE_460896 = "mceliece460896"
    MCELIECE_460896F = "mceliece460896f"
    MCELIECE_6688128 = "mceliece6688128"
    MCELIECE_6688128F = "mceliece6688128f"
    MCELIECE_6960119 = "mceliece6960119"
    MCELIECE_6960119F = "mceliece6960119f"
    MCELIECE_8192128 = "mceliece8192128"
    MCELIECE_8192128F = "mceliece8192128f"

class PostQuantumManager:
    """Manager for post-quantum cryptographic operations using certified libraries."""
    
    def __init__(self):
        """Initialize post-quantum manager with certified algorithms."""
        self.supported_algorithms = {
            PQAlgorithm.ML_KEM: {
                "name": "ML-KEM",
                "original_name": "Kyber",
                "type": "Key Encapsulation Mechanism",
                "variants": [PQVariant.KYBER_512, PQVariant.KYBER_768, PQVariant.KYBER_1024],
                "default_variant": PQVariant.KYBER_1024,
                "quantum_resistant": True,
                "standardization": "NIST FIPS 203",
                "cryptographic_base": "Module lattices"
            },
            PQAlgorithm.KYBER: {
                "name": "ML-KEM",
                "original_name": "Kyber",
                "type": "Key Encapsulation Mechanism",
                "variants": [PQVariant.KYBER_512, PQVariant.KYBER_768, PQVariant.KYBER_1024],
                "default_variant": PQVariant.KYBER_1024,
                "quantum_resistant": True,
                "standardization": "NIST FIPS 203",
                "cryptographic_base": "Module lattices"
            },
            PQAlgorithm.ML_DSA: {
                "name": "ML-DSA",
                "original_name": "Dilithium",
                "type": "Digital Signature",
                "variants": [PQVariant.DILITHIUM_2, PQVariant.DILITHIUM_3, PQVariant.DILITHIUM_5],
                "default_variant": PQVariant.DILITHIUM_3,
                "quantum_resistant": True,
                "standardization": "NIST FIPS 204",
                "cryptographic_base": "Module lattices"
            },
            PQAlgorithm.DILITHIUM: {
                "name": "ML-DSA",
                "original_name": "Dilithium",
                "type": "Digital Signature",
                "variants": [PQVariant.DILITHIUM_2, PQVariant.DILITHIUM_3, PQVariant.DILITHIUM_5],
                "default_variant": PQVariant.DILITHIUM_3,
                "quantum_resistant": True,
                "standardization": "NIST FIPS 204",
                "cryptographic_base": "Module lattices"
            },
            PQAlgorithm.FALCON: {
                "name": "FALCON",
                "original_name": "FALCON",
                "type": "Digital Signature",
                "variants": [PQVariant.FALCON_512, PQVariant.FALCON_1024, 
                            PQVariant.FALCON_PADDED_512, PQVariant.FALCON_PADDED_1024],
                "default_variant": PQVariant.FALCON_1024,
                "quantum_resistant": True,
                "standardization": "Expected NIST FIPS 206 (FN-DSA)",
                "cryptographic_base": "NTRU lattices"
            },
            PQAlgorithm.SPHINCS: {
                "name": "SPHINCS+",
                "original_name": "SPHINCS+",
                "type": "Digital Signature",
                "variants": [
                    PQVariant.SPHINCS_SHA2_128F, PQVariant.SPHINCS_SHA2_128S,
                    PQVariant.SPHINCS_SHA2_192F, PQVariant.SPHINCS_SHA2_192S,
                    PQVariant.SPHINCS_SHA2_256F, PQVariant.SPHINCS_SHA2_256S,
                    PQVariant.SPHINCS_SHAKE_128F, PQVariant.SPHINCS_SHAKE_128S,
                    PQVariant.SPHINCS_SHAKE_192F, PQVariant.SPHINCS_SHAKE_192S,
                    PQVariant.SPHINCS_SHAKE_256F, PQVariant.SPHINCS_SHAKE_256S
                ],
                "default_variant": PQVariant.SPHINCS_SHA2_256F,
                "quantum_resistant": True,
                "standardization": "NIST FIPS 205 (SLH-DSA)",
                "cryptographic_base": "Hash-based signatures"
            },
            PQAlgorithm.HQC: {
                "name": "HQC",
                "original_name": "HQC",
                "type": "Key Encapsulation Mechanism",
                "variants": [PQVariant.HQC_128, PQVariant.HQC_192, PQVariant.HQC_256],
                "default_variant": PQVariant.HQC_256,
                "quantum_resistant": True,
                "standardization": "NIST 2025 selection as ML-KEM backup",
                "cryptographic_base": "Error-correcting codes"
            },
            PQAlgorithm.MCELIECE: {
                "name": "Classic McEliece",
                "original_name": "Classic McEliece",
                "type": "Key Encapsulation Mechanism",
                "variants": [
                    PQVariant.MCELIECE_348864, PQVariant.MCELIECE_348864F,
                    PQVariant.MCELIECE_460896, PQVariant.MCELIECE_460896F,
                    PQVariant.MCELIECE_6688128, PQVariant.MCELIECE_6688128F,
                    PQVariant.MCELIECE_6960119, PQVariant.MCELIECE_6960119F,
                    PQVariant.MCELIECE_8192128, PQVariant.MCELIECE_8192128F
                ],
                "default_variant": PQVariant.MCELIECE_6688128,
                "quantum_resistant": True,
                "standardization": "NIST Round 4 alternate candidate",
                "cryptographic_base": "Error-correcting codes (Goppa codes)"
            },
            PQAlgorithm.HYBRID: {
                "name": "Hybrid",
                "original_name": "Hybrid",
                "type": "Combined Classical + Post-Quantum",
                "variants": ["hybrid_kyber_dilithium", "hybrid_all_algorithms"],
                "default_variant": "hybrid_kyber_dilithium",
                "quantum_resistant": True,
                "standardization": "Custom hybrid implementation",
                "cryptographic_base": "Multiple algorithms combined"
            }
        }
        
        logger.info("Post-quantum manager initialized with certified algorithms")
    
    def get_supported_algorithms(self) -> Dict[str, Any]:
        """Get list of supported post-quantum algorithms."""
        return self.supported_algorithms
    
    def get_algorithm_info(self, algorithm: PQAlgorithm, variant: Optional[str] = None) -> Dict[str, Any]:
        """Get information about a specific algorithm."""
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        algo_info = self.supported_algorithms[algorithm].copy()
        
        if algorithm in [PQAlgorithm.ML_KEM, PQAlgorithm.KYBER]:
            variant = variant or algo_info["default_variant"]
            specific_info = get_kyber_info(variant)
            algo_info.update(specific_info)
        elif algorithm in [PQAlgorithm.ML_DSA, PQAlgorithm.DILITHIUM]:
            variant = variant or algo_info["default_variant"]
            specific_info = get_dilithium_info(variant)
            algo_info.update(specific_info)
        elif algorithm == PQAlgorithm.FALCON:
            variant = variant or algo_info["default_variant"]
            specific_info = get_falcon_info(variant)
            algo_info.update(specific_info)
        elif algorithm == PQAlgorithm.SPHINCS:
            variant = variant or algo_info["default_variant"]
            specific_info = get_sphincs_info(variant)
            algo_info.update(specific_info)
        elif algorithm == PQAlgorithm.HQC:
            variant = variant or algo_info["default_variant"]
            specific_info = get_hqc_info(variant)
            algo_info.update(specific_info)
        elif algorithm == PQAlgorithm.MCELIECE:
            variant = variant or algo_info["default_variant"]
            specific_info = get_mceliece_info(variant)
            algo_info.update(specific_info)
        elif algorithm == PQAlgorithm.HYBRID:
            algo_info.update({
                "description": "Hybrid system combining multiple post-quantum algorithms",
                "security_level": 256,
                "quantum_resistant": True
            })
        
        return algo_info
    
    def generate_keypair(self, algorithm: PQAlgorithm, variant: Optional[str] = None) -> Tuple[str, str]:
        """Generate keypair for specified algorithm."""
        start_time = time.time()
        
        try:
            if algorithm in [PQAlgorithm.ML_KEM, PQAlgorithm.KYBER]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_kyber_keypair(variant)
                
            elif algorithm in [PQAlgorithm.ML_DSA, PQAlgorithm.DILITHIUM]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_dilithium_keypair(variant)
                
            elif algorithm == PQAlgorithm.FALCON:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_falcon_keypair(variant)
                
            elif algorithm == PQAlgorithm.SPHINCS:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_sphincs_keypair(variant)
                
            elif algorithm == PQAlgorithm.HQC:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_hqc_keypair(variant)
                
            elif algorithm == PQAlgorithm.MCELIECE:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                public_key, private_key = generate_mceliece_keypair(variant)
                
            elif algorithm == PQAlgorithm.HYBRID:
                # Generate multiple keypairs for hybrid approach
                kyber_pub, kyber_priv = generate_kyber_keypair("kyber1024")
                dilithium_pub, dilithium_priv = generate_dilithium_keypair("dilithium3")
                falcon_pub, falcon_priv = generate_falcon_keypair("falcon_1024")
                
                # Combine keys
                public_key = f"{kyber_pub}||{dilithium_pub}||{falcon_pub}"
                private_key = f"{kyber_priv}||{dilithium_priv}||{falcon_priv}"
                
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            processing_time = time.time() - start_time
            
            logger.info(f"Generated {algorithm} keypair in {processing_time:.3f}s")
            
            return public_key, private_key
            
        except Exception as e:
            logger.error(f"Keypair generation failed for {algorithm}: {e}")
            raise
    
    def encrypt(self, data: str, public_key: str, algorithm: PQAlgorithm, 
                variant: Optional[str] = None) -> str:
        """Encrypt data using post-quantum algorithm."""
        start_time = time.time()
        
        try:
            if algorithm in [PQAlgorithm.ML_KEM, PQAlgorithm.KYBER]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Use ML-KEM for key encapsulation, then symmetric encryption
                from cryptography.fernet import Fernet
                import base64
                
                # Encapsulate to get shared secret
                ciphertext, shared_secret = kyber_encapsulate(public_key, variant)
                
                # Use shared secret for symmetric encryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data.encode())
                
                # Combine ciphertext and encrypted data
                result = f"{ciphertext}||{base64.b64encode(encrypted_data).decode()}"
                
            elif algorithm == PQAlgorithm.HQC:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Use HQC for key encapsulation, then symmetric encryption
                from cryptography.fernet import Fernet
                import base64
                
                # Encapsulate to get shared secret
                ciphertext, shared_secret = hqc_encapsulate(public_key, variant)
                
                # Use shared secret for symmetric encryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data.encode())
                
                # Combine ciphertext and encrypted data
                result = f"{ciphertext}||{base64.b64encode(encrypted_data).decode()}"
                
            elif algorithm == PQAlgorithm.MCELIECE:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Use McEliece for key encapsulation, then symmetric encryption
                from cryptography.fernet import Fernet
                import base64
                
                # Encapsulate to get shared secret
                ciphertext, shared_secret = mceliece_encapsulate(public_key, variant)
                
                # Use shared secret for symmetric encryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data.encode())
                
                # Combine ciphertext and encrypted data
                result = f"{ciphertext}||{base64.b64encode(encrypted_data).decode()}"
                
            elif algorithm == PQAlgorithm.HYBRID:
                # Split hybrid public key and use first KEM algorithm
                parts = public_key.split("||")
                kyber_pub = parts[0]
                
                # Use Kyber for encryption
                result = self.encrypt(data, kyber_pub, PQAlgorithm.KYBER, "kyber1024")
                
            else:
                raise ValueError(f"Algorithm {algorithm} does not support encryption")
            
            processing_time = time.time() - start_time
            
            logger.info(f"Encrypted data using {algorithm} in {processing_time:.3f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Encryption failed for {algorithm}: {e}")
            raise
    
    def decrypt(self, encrypted_data: str, private_key: str, algorithm: PQAlgorithm,
                variant: Optional[str] = None) -> str:
        """Decrypt data using post-quantum algorithm."""
        start_time = time.time()
        
        try:
            if algorithm in [PQAlgorithm.ML_KEM, PQAlgorithm.KYBER]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Split ciphertext and encrypted data
                from cryptography.fernet import Fernet
                import base64
                
                ciphertext, encrypted_data_b64 = encrypted_data.split("||")
                
                # Decapsulate to get shared secret
                shared_secret = kyber_decapsulate(private_key, ciphertext, variant)
                
                # Use shared secret for symmetric decryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(base64.b64decode(encrypted_data_b64))
                
                result = decrypted_data.decode()
                
            elif algorithm == PQAlgorithm.HQC:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Split ciphertext and encrypted data
                from cryptography.fernet import Fernet
                import base64
                
                ciphertext, encrypted_data_b64 = encrypted_data.split("||")
                
                # Decapsulate to get shared secret
                shared_secret = hqc_decapsulate(private_key, ciphertext, variant)
                
                # Use shared secret for symmetric decryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(base64.b64decode(encrypted_data_b64))
                
                result = decrypted_data.decode()
                
            elif algorithm == PQAlgorithm.MCELIECE:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                
                # Split ciphertext and encrypted data
                from cryptography.fernet import Fernet
                import base64
                
                ciphertext, encrypted_data_b64 = encrypted_data.split("||")
                
                # Decapsulate to get shared secret
                shared_secret = mceliece_decapsulate(private_key, ciphertext, variant)
                
                # Use shared secret for symmetric decryption
                key = base64.urlsafe_b64encode(base64.b64decode(shared_secret)[:32])
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(base64.b64decode(encrypted_data_b64))
                
                result = decrypted_data.decode()
                
            elif algorithm == PQAlgorithm.HYBRID:
                # Split hybrid private key and use first KEM algorithm
                parts = private_key.split("||")
                kyber_priv = parts[0]
                
                # Use Kyber for decryption
                result = self.decrypt(encrypted_data, kyber_priv, PQAlgorithm.KYBER, "kyber1024")
                
            else:
                raise ValueError(f"Algorithm {algorithm} does not support decryption")
            
            processing_time = time.time() - start_time
            
            logger.info(f"Decrypted data using {algorithm} in {processing_time:.3f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Decryption failed for {algorithm}: {e}")
            raise
    
    def sign(self, data: str, private_key: str, algorithm: PQAlgorithm,
             variant: Optional[str] = None) -> str:
        """Sign data using post-quantum algorithm."""
        start_time = time.time()
        
        try:
            if algorithm in [PQAlgorithm.ML_DSA, PQAlgorithm.DILITHIUM]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                signature = dilithium_sign(data, private_key, variant)
                
            elif algorithm == PQAlgorithm.FALCON:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                signature = falcon_sign(data, private_key, variant)
                
            elif algorithm == PQAlgorithm.SPHINCS:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                signature = sphincs_sign(data, private_key, variant)
                
            elif algorithm == PQAlgorithm.HYBRID:
                # Split hybrid private key and use multiple signature algorithms
                parts = private_key.split("||")
                dilithium_priv = parts[1]
                falcon_priv = parts[2]
                
                # Sign with multiple algorithms
                dilithium_sig = dilithium_sign(data, dilithium_priv, "dilithium3")
                falcon_sig = falcon_sign(data, falcon_priv, "falcon_1024")
                
                # Combine signatures
                signature = f"{dilithium_sig}||{falcon_sig}"
                
            else:
                raise ValueError(f"Algorithm {algorithm} does not support signing")
            
            processing_time = time.time() - start_time
            
            logger.info(f"Signed data using {algorithm} in {processing_time:.3f}s")
            
            return signature
            
        except Exception as e:
            logger.error(f"Signing failed for {algorithm}: {e}")
            raise
    
    def verify(self, data: str, signature: str, public_key: str, algorithm: PQAlgorithm,
               variant: Optional[str] = None) -> bool:
        """Verify signature using post-quantum algorithm."""
        start_time = time.time()
        
        try:
            if algorithm in [PQAlgorithm.ML_DSA, PQAlgorithm.DILITHIUM]:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                is_valid = dilithium_verify(data, signature, public_key, variant)
                
            elif algorithm == PQAlgorithm.FALCON:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                is_valid = falcon_verify(data, signature, public_key, variant)
                
            elif algorithm == PQAlgorithm.SPHINCS:
                variant = variant or self.supported_algorithms[algorithm]["default_variant"]
                is_valid = sphincs_verify(data, signature, public_key, variant)
                
            elif algorithm == PQAlgorithm.HYBRID:
                # Split hybrid public key and signatures
                pub_parts = public_key.split("||")
                sig_parts = signature.split("||")
                
                dilithium_pub = pub_parts[1]
                falcon_pub = pub_parts[2]
                dilithium_sig = sig_parts[0]
                falcon_sig = sig_parts[1]
                
                # Verify with multiple algorithms (all must pass)
                dilithium_valid = dilithium_verify(data, dilithium_sig, dilithium_pub, "dilithium3")
                falcon_valid = falcon_verify(data, falcon_sig, falcon_pub, "falcon_1024")
                
                is_valid = dilithium_valid and falcon_valid
                
            else:
                raise ValueError(f"Algorithm {algorithm} does not support verification")
            
            processing_time = time.time() - start_time
            
            logger.info(f"Verified signature using {algorithm} in {processing_time:.3f}s: {is_valid}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Verification failed for {algorithm}: {e}")
            return False
    
    def get_all_supported_variants(self) -> Dict[str, List[str]]:
        """Get all supported variants for all algorithms."""
        return {
            "ML-KEM/Kyber": ["kyber512", "kyber768", "kyber1024"],
            "ML-DSA/Dilithium": ["dilithium2", "dilithium3", "dilithium5"],
            "FALCON": ["falcon_512", "falcon_1024", "falcon_padded_512", "falcon_padded_1024"],
            "SPHINCS+": [
                "sphincs_sha2_128f_simple", "sphincs_sha2_128s_simple",
                "sphincs_sha2_192f_simple", "sphincs_sha2_192s_simple",
                "sphincs_sha2_256f_simple", "sphincs_sha2_256s_simple",
                "sphincs_shake_128f_simple", "sphincs_shake_128s_simple",
                "sphincs_shake_192f_simple", "sphincs_shake_192s_simple",
                "sphincs_shake_256f_simple", "sphincs_shake_256s_simple"
            ],
            "HQC": ["hqc_128", "hqc_192", "hqc_256"],
            "Classic McEliece": [
                "mceliece348864", "mceliece348864f", "mceliece460896", "mceliece460896f",
                "mceliece6688128", "mceliece6688128f", "mceliece6960119", "mceliece6960119f",
                "mceliece8192128", "mceliece8192128f"
            ]
        }
    
    def get_performance_comparison(self) -> Dict[str, Dict[str, Any]]:
        """Get performance comparison of all algorithms."""
        return {
            "ML-KEM (Kyber)": {
                "keygen_time": "Fast",
                "encrypt_time": "Fast",
                "decrypt_time": "Fast",
                "key_sizes": "Small to medium",
                "ciphertext_size": "Small",
                "standardization": "NIST FIPS 203"
            },
            "ML-DSA (Dilithium)": {
                "keygen_time": "Fast",
                "sign_time": "Fast",
                "verify_time": "Fast",
                "key_sizes": "Medium",
                "signature_size": "Medium",
                "standardization": "NIST FIPS 204"
            },
            "FALCON": {
                "keygen_time": "Slow",
                "sign_time": "Medium",
                "verify_time": "Fast",
                "key_sizes": "Small",
                "signature_size": "Small",
                "standardization": "Expected NIST FIPS 206"
            },
            "SPHINCS+": {
                "keygen_time": "Fast",
                "sign_time": "Very slow",
                "verify_time": "Fast",
                "key_sizes": "Small",
                "signature_size": "Large",
                "standardization": "NIST FIPS 205"
            },
            "HQC": {
                "keygen_time": "Fast",
                "encrypt_time": "Fast",
                "decrypt_time": "Fast",
                "key_sizes": "Large",
                "ciphertext_size": "Large",
                "standardization": "NIST 2025 backup"
            },
            "Classic McEliece": {
                "keygen_time": "Fast",
                "encrypt_time": "Fast",
                "decrypt_time": "Fast",
                "key_sizes": "Very large",
                "ciphertext_size": "Small",
                "standardization": "NIST Round 4 alternate"
            }
        }

# Global instance
pq_manager = PostQuantumManager()

# Convenience functions
def get_pq_manager() -> PostQuantumManager:
    """Get the global post-quantum manager instance."""
    return pq_manager

def list_all_algorithms() -> Dict[str, Any]:
    """List all available post-quantum algorithms and their variants."""
    manager = get_pq_manager()
    return {
        "algorithms": manager.get_supported_algorithms(),
        "variants": manager.get_all_supported_variants(),
        "performance": manager.get_performance_comparison()
    }

def quick_test_algorithm(algorithm: PQAlgorithm, variant: Optional[str] = None) -> Dict[str, Any]:
    """Quick test of an algorithm to verify it's working."""
    manager = get_pq_manager()
    
    try:
        # Test keypair generation
        public_key, private_key = manager.generate_keypair(algorithm, variant)
        
        # Test encryption/decryption for KEMs
        if algorithm in [PQAlgorithm.ML_KEM, PQAlgorithm.KYBER, PQAlgorithm.HQC, PQAlgorithm.MCELIECE]:
            test_data = "Hello, post-quantum world!"
            encrypted = manager.encrypt(test_data, public_key, algorithm, variant)
            decrypted = manager.decrypt(encrypted, private_key, algorithm, variant)
            encryption_works = test_data == decrypted
        else:
            encryption_works = None
        
        # Test signing/verification for DSAs
        if algorithm in [PQAlgorithm.ML_DSA, PQAlgorithm.DILITHIUM, PQAlgorithm.FALCON, PQAlgorithm.SPHINCS]:
            test_data = "Hello, post-quantum signatures!"
            signature = manager.sign(test_data, private_key, algorithm, variant)
            signature_valid = manager.verify(test_data, signature, public_key, algorithm, variant)
        else:
            signature_valid = None
        
        # Test hybrid
        if algorithm == PQAlgorithm.HYBRID:
            test_data = "Hello, hybrid world!"
            encrypted = manager.encrypt(test_data, public_key, algorithm, variant)
            decrypted = manager.decrypt(encrypted, private_key, algorithm, variant)
            encryption_works = test_data == decrypted
            
            signature = manager.sign(test_data, private_key, algorithm, variant)
            signature_valid = manager.verify(test_data, signature, public_key, algorithm, variant)
        
        return {
            "algorithm": algorithm.value,
            "variant": variant,
            "keypair_generation": True,
            "encryption_works": encryption_works,
            "signature_valid": signature_valid,
            "status": "SUCCESS"
        }
        
    except Exception as e:
        return {
            "algorithm": algorithm.value,
            "variant": variant,
            "status": "FAILED",
            "error": str(e)
        }

# Example usage and testing
if __name__ == "__main__":
    print("Testing Post-Quantum Cryptography Manager with certified algorithms...")
    
    # Test key algorithms
    test_algorithms = [
        (PQAlgorithm.ML_KEM, "kyber1024"),
        (PQAlgorithm.ML_DSA, "dilithium3"),
        (PQAlgorithm.FALCON, "falcon_1024"),
        (PQAlgorithm.SPHINCS, "sphincs_sha2_256f_simple"),
        (PQAlgorithm.HQC, "hqc_256"),
        (PQAlgorithm.MCELIECE, "mceliece348864"),
        (PQAlgorithm.HYBRID, None)
    ]
    
    for algorithm, variant in test_algorithms:
        print(f"\n=== Testing {algorithm.value} ({variant}) ===")
        result = quick_test_algorithm(algorithm, variant)
        print(f"Status: {result['status']}")
        if result['status'] == 'SUCCESS':
            print(f"Keypair generation: ✓")
            if result['encryption_works'] is not None:
                print(f"Encryption/Decryption: {'✓' if result['encryption_works'] else '✗'}")
            if result['signature_valid'] is not None:
                print(f"Signature/Verification: {'✓' if result['signature_valid'] else '✗'}")
        else:
            print(f"Error: {result['error']}")
    
    print("\n=== All Supported Algorithms ===")
    all_info = list_all_algorithms()
    for algo_name, variants in all_info["variants"].items():
        print(f"{algo_name}: {len(variants)} variants")