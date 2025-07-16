"""
Unit tests for encryption modules.
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'crypto-core'))

from crypto_core.post_quantum.kyber import KyberKEM, generate_kyber_keypair
from crypto_core.post_quantum.dilithium import DilithiumSigner, generate_dilithium_keypair
from crypto_core.hybrid.hybrid_encryptor import HybridEncryptor
from crypto_core.classical.aes import AESEncryption
from crypto_core.classical.rsa import RSAEncryption


class TestKyberKEM:
    """Test cases for Kyber key encapsulation mechanism."""
    
    def test_kyber_keypair_generation(self):
        """Test Kyber keypair generation."""
        kyber = KyberKEM("kyber1024")
        public_key, private_key = kyber.generate_keypair()
        
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        assert len(public_key) > 0
        assert len(private_key) > 0
    
    def test_kyber_encapsulation_decapsulation(self):
        """Test Kyber encapsulation and decapsulation."""
        kyber = KyberKEM("kyber1024")
        public_key, private_key = kyber.generate_keypair()
        
        # Encapsulate
        ciphertext, shared_secret1 = kyber.encapsulate(public_key)
        
        # Decapsulate
        shared_secret2 = kyber.decapsulate(private_key, ciphertext)
        
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32  # 256 bits
    
    def test_kyber_variants(self):
        """Test different Kyber variants."""
        variants = ["kyber512", "kyber768", "kyber1024"]
        
        for variant in variants:
            kyber = KyberKEM(variant)
            public_key, private_key = kyber.generate_keypair()
            
            assert isinstance(public_key, bytes)
            assert isinstance(private_key, bytes)
            
            # Test security levels
            if variant == "kyber512":
                assert kyber.get_security_level() == 128
            elif variant == "kyber768":
                assert kyber.get_security_level() == 192
            elif variant == "kyber1024":
                assert kyber.get_security_level() == 256
    
    def test_kyber_serialization(self):
        """Test Kyber key serialization."""
        kyber = KyberKEM("kyber1024")
        public_key, private_key = kyber.generate_keypair()
        
        # Serialize keys
        public_key_str = kyber.serialize_public_key(public_key)
        private_key_str = kyber.serialize_private_key(private_key)
        
        # Deserialize keys
        public_key_deserialized = kyber.deserialize_public_key(public_key_str)
        private_key_deserialized = kyber.deserialize_private_key(private_key_str)
        
        assert public_key == public_key_deserialized
        assert private_key == private_key_deserialized
    
    def test_invalid_kyber_variant(self):
        """Test invalid Kyber variant."""
        with pytest.raises(ValueError):
            KyberKEM("invalid_variant")


class TestDilithiumSigner:
    """Test cases for Dilithium digital signatures."""
    
    def test_dilithium_keypair_generation(self):
        """Test Dilithium keypair generation."""
        dilithium = DilithiumSigner("dilithium3")
        public_key, private_key = dilithium.generate_keypair()
        
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        assert len(public_key) > 0
        assert len(private_key) > 0
    
    def test_dilithium_sign_verify(self):
        """Test Dilithium signing and verification."""
        dilithium = DilithiumSigner("dilithium3")
        public_key, private_key = dilithium.generate_keypair()
        
        message = b"Test message for signing"
        
        # Sign message
        signature = dilithium.sign(private_key, message)
        
        # Verify signature
        is_valid = dilithium.verify(public_key, message, signature)
        
        assert is_valid is True
        assert isinstance(signature, bytes)
    
    def test_dilithium_invalid_signature(self):
        """Test Dilithium with invalid signature."""
        dilithium = DilithiumSigner("dilithium3")
        public_key, private_key = dilithium.generate_keypair()
        
        message = b"Test message"
        wrong_message = b"Wrong message"
        
        # Sign original message
        signature = dilithium.sign(private_key, message)
        
        # Verify with wrong message
        is_valid = dilithium.verify(public_key, wrong_message, signature)
        
        assert is_valid is False
    
    def test_dilithium_variants(self):
        """Test different Dilithium variants."""
        variants = ["dilithium2", "dilithium3", "dilithium5"]
        
        for variant in variants:
            dilithium = DilithiumSigner(variant)
            public_key, private_key = dilithium.generate_keypair()
            
            assert isinstance(public_key, bytes)
            assert isinstance(private_key, bytes)


class TestHybridEncryptor:
    """Test cases for hybrid encryption."""
    
    def test_hybrid_encryption_decryption(self):
        """Test hybrid encryption and decryption."""
        encryptor = HybridEncryptor()
        
        message = b"This is a test message for hybrid encryption"
        
        # Encrypt
        encrypted_data = encryptor.encrypt(message)
        
        # Decrypt
        decrypted_data = encryptor.decrypt(encrypted_data)
        
        assert decrypted_data == message
    
    def test_hybrid_key_exchange(self):
        """Test hybrid key exchange."""
        encryptor = HybridEncryptor()
        
        # Generate keys
        keys = encryptor.generate_keys()
        
        assert 'kyber_public' in keys
        assert 'kyber_private' in keys
        assert 'rsa_public' in keys
        assert 'rsa_private' in keys
    
    def test_algorithm_selection(self):
        """Test algorithm selection based on threat level."""
        encryptor = HybridEncryptor()
        
        # Low threat - should use classical
        algorithm = encryptor.select_algorithm(threat_level=0.2)
        assert algorithm in ['rsa', 'aes']
        
        # High threat - should use post-quantum
        algorithm = encryptor.select_algorithm(threat_level=0.9)
        assert algorithm in ['kyber', 'dilithium']


class TestAESEncryption:
    """Test cases for AES encryption."""
    
    def test_aes_encryption_decryption(self):
        """Test AES encryption and decryption."""
        aes = AESEncryption()
        
        message = b"Test message for AES encryption"
        key = aes.generate_key()
        
        # Encrypt
        encrypted_data = aes.encrypt(message, key)
        
        # Decrypt
        decrypted_data = aes.decrypt(encrypted_data, key)
        
        assert decrypted_data == message
    
    def test_aes_key_generation(self):
        """Test AES key generation."""
        aes = AESEncryption()
        key = aes.generate_key()
        
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits
    
    def test_aes_invalid_key(self):
        """Test AES with invalid key."""
        aes = AESEncryption()
        
        message = b"Test message"
        invalid_key = b"short_key"
        
        with pytest.raises(ValueError):
            aes.encrypt(message, invalid_key)


class TestRSAEncryption:
    """Test cases for RSA encryption."""
    
    def test_rsa_keypair_generation(self):
        """Test RSA keypair generation."""
        rsa = RSAEncryption()
        public_key, private_key = rsa.generate_keypair()
        
        assert public_key is not None
        assert private_key is not None
    
    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption."""
        rsa = RSAEncryption()
        public_key, private_key = rsa.generate_keypair()
        
        message = b"Test message for RSA"
        
        # Encrypt
        encrypted_data = rsa.encrypt(message, public_key)
        
        # Decrypt
        decrypted_data = rsa.decrypt(encrypted_data, private_key)
        
        assert decrypted_data == message
    
    def test_rsa_sign_verify(self):
        """Test RSA signing and verification."""
        rsa = RSAEncryption()
        public_key, private_key = rsa.generate_keypair()
        
        message = b"Test message for signing"
        
        # Sign
        signature = rsa.sign(message, private_key)
        
        # Verify
        is_valid = rsa.verify(message, signature, public_key)
        
        assert is_valid is True


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    def test_generate_kyber_keypair(self):
        """Test convenience function for Kyber keypair generation."""
        public_key, private_key = generate_kyber_keypair("kyber1024")
        
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        assert len(public_key) > 0
        assert len(private_key) > 0
    
    def test_generate_dilithium_keypair(self):
        """Test convenience function for Dilithium keypair generation."""
        public_key, private_key = generate_dilithium_keypair("dilithium3")
        
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        assert len(public_key) > 0
        assert len(private_key) > 0


if __name__ == "__main__":
    pytest.main([__file__])