"""
Integration tests for hybrid encryption flow.
"""
import pytest
import sys
import os
import asyncio
import time
from unittest.mock import patch, MagicMock

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'crypto-core'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'ai-engine'))

from crypto_core.hybrid.hybrid_encryptor import HybridEncryptor
from ai_engine.decision_engine.decision_tree import DecisionEngine
from ai_engine.threat_detection.quantum_anomaly import QuantumAnomalyDetector
from backend.services.encryption_service import EncryptionService
from backend.services.ai_decision_service import AIDecisionService


class TestHybridEncryptionFlow:
    """Test cases for complete hybrid encryption flow."""
    
    def test_end_to_end_encryption_flow(self):
        """Test complete encryption flow from API to crypto layer."""
        # Initialize services
        encryption_service = EncryptionService()
        ai_service = AIDecisionService()
        
        # Mock user request
        user_data = {
            'message': 'This is a test message for encryption',
            'user_id': 'test_user_123',
            'data_sensitivity': 'high',
            'performance_priority': 'medium'
        }
        
        # Mock threat assessment
        threat_context = {
            'source_ip': '192.168.1.100',
            'recent_threats': [],
            'user_behavior': 'normal',
            'time_of_day': '14:30'
        }
        
        # AI decision for algorithm selection
        algorithm_decision = ai_service.select_encryption_algorithm(
            user_data, threat_context
        )
        
        assert algorithm_decision['algorithm'] in ['hybrid', 'post_quantum', 'classical']
        assert 'confidence' in algorithm_decision
        
        # Encryption based on AI decision
        encrypted_result = encryption_service.encrypt(
            user_data['message'],
            algorithm=algorithm_decision['algorithm'],
            user_id=user_data['user_id']
        )
        
        assert 'encrypted_data' in encrypted_result
        assert 'key_info' in encrypted_result
        assert 'algorithm_used' in encrypted_result
        
        # Decryption
        decrypted_result = encryption_service.decrypt(
            encrypted_result['encrypted_data'],
            encrypted_result['key_info'],
            user_id=user_data['user_id']
        )
        
        assert decrypted_result == user_data['message']
    
    def test_threat_adaptive_encryption(self):
        """Test encryption adaptation based on threat level."""
        encryption_service = EncryptionService()
        ai_service = AIDecisionService()
        threat_detector = QuantumAnomalyDetector()
        
        # Mock low threat scenario
        low_threat_data = {
            'packet_size': 1024,
            'frequency': 2.4,
            'encryption_type': 'classical',
            'source_ip': '192.168.1.50'
        }
        
        # Should select classical encryption for low threat
        is_anomaly, confidence = threat_detector.detect_anomaly(low_threat_data)
        threat_level = 0.2 if not is_anomaly else 0.8
        
        algorithm = ai_service.select_algorithm_by_threat(threat_level)
        
        if threat_level < 0.5:
            assert algorithm in ['aes', 'rsa']
        else:
            assert algorithm in ['kyber', 'dilithium']
    
    def test_performance_vs_security_tradeoff(self):
        """Test performance vs security tradeoff decisions."""
        encryption_service = EncryptionService()
        
        # Test data of different sizes
        test_sizes = [1024, 10240, 102400, 1048576]  # 1KB to 1MB
        
        for size in test_sizes:
            test_data = b'A' * size
            
            # Measure classical encryption
            classical_result = encryption_service.encrypt(
                test_data,
                algorithm='classical',
                measure_performance=True
            )
            
            # Measure post-quantum encryption
            pq_result = encryption_service.encrypt(
                test_data,
                algorithm='post_quantum',
                measure_performance=True
            )
            
            # Classical should be faster for small data
            if size < 10240:
                assert classical_result['performance']['encryption_time'] < pq_result['performance']['encryption_time']
            
            # Both should successfully encrypt and decrypt
            assert classical_result['status'] == 'success'
            assert pq_result['status'] == 'success'
    
    def test_key_management_integration(self):
        """Test key management integration."""
        encryption_service = EncryptionService()
        
        # Generate keys for different algorithms
        kyber_keys = encryption_service.generate_keys('kyber')
        dilithium_keys = encryption_service.generate_keys('dilithium')
        rsa_keys = encryption_service.generate_keys('rsa')
        
        # Verify key generation
        assert 'public_key' in kyber_keys
        assert 'private_key' in kyber_keys
        assert 'public_key' in dilithium_keys
        assert 'private_key' in dilithium_keys
        assert 'public_key' in rsa_keys
        assert 'private_key' in rsa_keys
        
        # Test key rotation
        old_keys = kyber_keys.copy()
        new_keys = encryption_service.rotate_keys('kyber', old_keys)
        
        assert new_keys['public_key'] != old_keys['public_key']
        assert new_keys['private_key'] != old_keys['private_key']
    
    def test_multi_algorithm_compatibility(self):
        """Test compatibility between different algorithms."""
        encryption_service = EncryptionService()
        
        test_message = b"Test message for compatibility"
        
        # Encrypt with hybrid approach
        hybrid_result = encryption_service.encrypt(
            test_message,
            algorithm='hybrid'
        )
        
        # Should contain both classical and post-quantum components
        assert 'classical_component' in hybrid_result
        assert 'post_quantum_component' in hybrid_result
        
        # Decrypt and verify
        decrypted = encryption_service.decrypt(
            hybrid_result['encrypted_data'],
            hybrid_result['key_info']
        )
        
        assert decrypted == test_message
    
    def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms."""
        encryption_service = EncryptionService()
        
        # Test invalid algorithm
        with pytest.raises(ValueError):
            encryption_service.encrypt("test", algorithm="invalid_algorithm")
        
        # Test corrupted data
        corrupted_data = b"corrupted_encrypted_data"
        with pytest.raises(Exception):
            encryption_service.decrypt(corrupted_data, {})
        
        # Test recovery from failures
        recovery_result = encryption_service.encrypt_with_fallback(
            "test message",
            primary_algorithm="invalid_algorithm",
            fallback_algorithm="aes"
        )
        
        assert recovery_result['status'] == 'success'
        assert recovery_result['algorithm_used'] == 'aes'
    
    def test_concurrent_encryption_operations(self):
        """Test concurrent encryption operations."""
        encryption_service = EncryptionService()
        
        async def encrypt_task(message, algorithm):
            return encryption_service.encrypt(message, algorithm=algorithm)
        
        async def run_concurrent_tests():
            # Create multiple encryption tasks
            tasks = []
            for i in range(10):
                message = f"Test message {i}"
                algorithm = 'hybrid' if i % 2 == 0 else 'classical'
                tasks.append(encrypt_task(message, algorithm))
            
            # Run tasks concurrently
            results = await asyncio.gather(*tasks)
            
            # Verify all tasks completed successfully
            for result in results:
                assert result['status'] == 'success'
                assert 'encrypted_data' in result
        
        # Run the concurrent test
        asyncio.run(run_concurrent_tests())
    
    def test_real_time_threat_response(self):
        """Test real-time threat response integration."""
        encryption_service = EncryptionService()
        ai_service = AIDecisionService()
        
        # Mock real-time threat detection
        threat_events = [
            {'type': 'quantum_attack', 'severity': 'high', 'timestamp': 1234567890},
            {'type': 'key_compromise', 'severity': 'critical', 'timestamp': 1234567891},
            {'type': 'anomaly_detected', 'severity': 'medium', 'timestamp': 1234567892}
        ]
        
        for event in threat_events:
            # AI should recommend appropriate response
            response = ai_service.recommend_threat_response(event)
            
            assert 'action' in response
            assert 'urgency' in response
            assert response['action'] in ['upgrade_encryption', 'rotate_keys', 'monitor']
            
            # Encryption service should adapt to threat
            if response['action'] == 'upgrade_encryption':
                result = encryption_service.upgrade_encryption_level(event)
                assert result['new_algorithm'] in ['kyber', 'dilithium']
            
            elif response['action'] == 'rotate_keys':
                result = encryption_service.emergency_key_rotation(event)
                assert result['status'] == 'success'
    
    def test_blockchain_integration_flow(self):
        """Test blockchain integration with encryption."""
        encryption_service = EncryptionService()
        
        # Mock blockchain transaction
        transaction_data = {
            'from': '0x1234567890123456789012345678901234567890',
            'to': '0x0987654321098765432109876543210987654321',
            'value': 1000000000000000000,  # 1 ETH in wei
            'data': 'quantum_safe_transaction'
        }
        
        # Sign transaction with post-quantum signature
        signed_transaction = encryption_service.sign_blockchain_transaction(
            transaction_data,
            algorithm='dilithium'
        )
        
        assert 'signature' in signed_transaction
        assert 'public_key' in signed_transaction
        assert 'algorithm' in signed_transaction
        
        # Verify signature
        is_valid = encryption_service.verify_blockchain_signature(
            signed_transaction,
            transaction_data
        )
        
        assert is_valid is True
    
    def test_audit_and_compliance(self):
        """Test audit trail and compliance features."""
        encryption_service = EncryptionService()
        
        # Perform various operations
        operations = [
            {'operation': 'encrypt', 'data': 'test1', 'algorithm': 'kyber'},
            {'operation': 'decrypt', 'data': 'encrypted_test1', 'algorithm': 'kyber'},
            {'operation': 'generate_keys', 'algorithm': 'dilithium'},
            {'operation': 'rotate_keys', 'algorithm': 'rsa'}
        ]
        
        for op in operations:
            result = encryption_service.execute_with_audit(op)
            assert result['status'] == 'success'
            assert 'audit_id' in result
        
        # Retrieve audit logs
        audit_logs = encryption_service.get_audit_logs()
        
        assert len(audit_logs) >= len(operations)
        assert all('timestamp' in log for log in audit_logs)
        assert all('user_id' in log for log in audit_logs)
        assert all('operation' in log for log in audit_logs)
    
    def test_scalability_and_load_handling(self):
        """Test scalability and load handling."""
        encryption_service = EncryptionService()
        
        # Simulate high load
        num_operations = 1000
        
        start_time = time.time()
        
        for i in range(num_operations):
            message = f"Load test message {i}"
            result = encryption_service.encrypt(message, algorithm='hybrid')
            assert result['status'] == 'success'
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should handle load within reasonable time
        assert total_time < 60  # Should complete within 1 minute
        
        # Check performance metrics
        performance_metrics = encryption_service.get_performance_metrics()
        assert 'average_encryption_time' in performance_metrics
        assert 'throughput' in performance_metrics
        assert performance_metrics['throughput'] > 10  # At least 10 ops/sec


if __name__ == "__main__":
    pytest.main([__file__])