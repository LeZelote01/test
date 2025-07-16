"""
Unit tests for AI modules.
"""
import pytest
import sys
import os
import numpy as np
from unittest.mock import patch, MagicMock

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'ai-engine'))

from ai_engine.threat_detection.quantum_anomaly import QuantumAnomalyDetector
from ai_engine.threat_detection.threat_scanner import ThreatScanner
from ai_engine.decision_engine.decision_tree import DecisionEngine
from ai_engine.decision_engine.reinforcement_learning import RLAgent
from ai_engine.monitoring.real_time_monitor import RealTimeMonitor


class TestQuantumAnomalyDetector:
    """Test cases for quantum anomaly detection."""
    
    def test_anomaly_detector_initialization(self):
        """Test anomaly detector initialization."""
        detector = QuantumAnomalyDetector()
        
        assert detector.model is not None
        assert detector.threshold == 0.8
        assert detector.is_trained is False
    
    def test_feature_extraction(self):
        """Test feature extraction from network data."""
        detector = QuantumAnomalyDetector()
        
        # Mock network data
        network_data = {
            'packet_size': 1024,
            'frequency': 2.4,
            'encryption_type': 'post_quantum',
            'source_ip': '192.168.1.1',
            'destination_ip': '192.168.1.100',
            'protocol': 'TCP',
            'timestamp': 1234567890
        }
        
        features = detector.extract_features(network_data)
        
        assert isinstance(features, np.ndarray)
        assert len(features) > 0
    
    def test_anomaly_detection(self):
        """Test anomaly detection."""
        detector = QuantumAnomalyDetector()
        
        # Mock training data
        training_data = []
        for i in range(100):
            training_data.append({
                'packet_size': np.random.randint(64, 1500),
                'frequency': np.random.uniform(1.0, 5.0),
                'encryption_type': 'classical',
                'source_ip': f'192.168.1.{i}',
                'destination_ip': '192.168.1.100',
                'protocol': 'TCP',
                'timestamp': 1234567890 + i
            })
        
        # Train model
        detector.train(training_data)
        
        assert detector.is_trained is True
        
        # Test normal data
        normal_data = {
            'packet_size': 1024,
            'frequency': 2.4,
            'encryption_type': 'classical',
            'source_ip': '192.168.1.50',
            'destination_ip': '192.168.1.100',
            'protocol': 'TCP',
            'timestamp': 1234567890
        }
        
        is_anomaly, confidence = detector.detect_anomaly(normal_data)
        assert isinstance(is_anomaly, bool)
        assert 0 <= confidence <= 1
    
    def test_quantum_threat_detection(self):
        """Test quantum-specific threat detection."""
        detector = QuantumAnomalyDetector()
        
        # Mock quantum threat indicators
        quantum_threat_data = {
            'packet_size': 4096,  # Large quantum packets
            'frequency': 10.0,    # High frequency
            'encryption_type': 'quantum_vulnerable',
            'source_ip': '10.0.0.1',
            'destination_ip': '192.168.1.100',
            'protocol': 'UDP',
            'timestamp': 1234567890,
            'quantum_signature': True
        }
        
        # This should trigger quantum threat detection
        threat_level = detector.assess_quantum_threat(quantum_threat_data)
        
        assert 0 <= threat_level <= 1
        assert threat_level > 0.5  # Should be high for quantum threats
    
    def test_model_update(self):
        """Test model update with new data."""
        detector = QuantumAnomalyDetector()
        
        # Initial training
        initial_data = [{'packet_size': 1024, 'frequency': 2.4}] * 50
        detector.train(initial_data)
        
        # Update with new data
        new_data = [{'packet_size': 2048, 'frequency': 4.8}] * 25
        detector.update_model(new_data)
        
        assert detector.is_trained is True


class TestThreatScanner:
    """Test cases for threat scanner."""
    
    def test_threat_scanner_initialization(self):
        """Test threat scanner initialization."""
        scanner = ThreatScanner()
        
        assert scanner.scan_interval == 60  # 1 minute
        assert scanner.is_running is False
        assert len(scanner.threat_patterns) > 0
    
    def test_signature_based_detection(self):
        """Test signature-based threat detection."""
        scanner = ThreatScanner()
        
        # Mock malicious patterns
        malicious_data = {
            'payload': b'quantum_exploit_signature',
            'source_ip': '192.168.1.100',
            'patterns': ['exploit', 'quantum', 'attack']
        }
        
        threats = scanner.scan_signatures(malicious_data)
        
        assert isinstance(threats, list)
        assert len(threats) > 0
    
    def test_behavioral_analysis(self):
        """Test behavioral threat analysis."""
        scanner = ThreatScanner()
        
        # Mock behavioral data
        behavioral_data = {
            'requests_per_minute': 1000,  # High request rate
            'unique_endpoints': 50,
            'error_rate': 0.3,
            'response_time_variance': 0.8
        }
        
        risk_score = scanner.analyze_behavior(behavioral_data)
        
        assert 0 <= risk_score <= 1
        assert risk_score > 0.5  # Should be high for suspicious behavior
    
    def test_quantum_vulnerability_scan(self):
        """Test quantum vulnerability scanning."""
        scanner = ThreatScanner()
        
        # Mock system configuration
        system_config = {
            'encryption_algorithms': ['RSA-2048', 'AES-256'],
            'tls_version': '1.2',
            'quantum_ready': False,
            'key_sizes': {'RSA': 2048, 'ECC': 256}
        }
        
        vulnerabilities = scanner.scan_quantum_vulnerabilities(system_config)
        
        assert isinstance(vulnerabilities, list)
        assert len(vulnerabilities) > 0  # Should find quantum vulnerabilities
    
    def test_threat_correlation(self):
        """Test threat correlation and prioritization."""
        scanner = ThreatScanner()
        
        # Mock multiple threats
        threats = [
            {'type': 'quantum_attack', 'severity': 'high', 'confidence': 0.9},
            {'type': 'ddos', 'severity': 'medium', 'confidence': 0.7},
            {'type': 'malware', 'severity': 'low', 'confidence': 0.3}
        ]
        
        prioritized_threats = scanner.correlate_threats(threats)
        
        assert isinstance(prioritized_threats, list)
        assert len(prioritized_threats) == len(threats)
        # Should be sorted by priority
        assert prioritized_threats[0]['severity'] == 'high'


class TestDecisionEngine:
    """Test cases for decision engine."""
    
    def test_decision_engine_initialization(self):
        """Test decision engine initialization."""
        engine = DecisionEngine()
        
        assert engine.decision_tree is not None
        assert engine.confidence_threshold == 0.7
    
    def test_algorithm_selection(self):
        """Test algorithm selection based on threat level."""
        engine = DecisionEngine()
        
        # Low threat scenario
        low_threat_context = {
            'threat_level': 0.2,
            'performance_priority': 'high',
            'data_sensitivity': 'low'
        }
        
        algorithm = engine.select_algorithm(low_threat_context)
        assert algorithm in ['AES', 'RSA']
        
        # High threat scenario
        high_threat_context = {
            'threat_level': 0.9,
            'performance_priority': 'low',
            'data_sensitivity': 'high'
        }
        
        algorithm = engine.select_algorithm(high_threat_context)
        assert algorithm in ['Kyber', 'Dilithium']
    
    def test_security_policy_decision(self):
        """Test security policy decision making."""
        engine = DecisionEngine()
        
        # Mock security event
        security_event = {
            'event_type': 'failed_authentication',
            'frequency': 10,
            'source_ip': '192.168.1.100',
            'time_window': 300,  # 5 minutes
            'user_agent': 'suspicious_bot'
        }
        
        policy_decision = engine.make_security_decision(security_event)
        
        assert 'action' in policy_decision
        assert 'confidence' in policy_decision
        assert policy_decision['action'] in ['allow', 'block', 'monitor']
    
    def test_adaptive_learning(self):
        """Test adaptive learning from decisions."""
        engine = DecisionEngine()
        
        # Mock decision feedback
        decision_feedback = {
            'decision_id': 'test_123',
            'outcome': 'success',
            'effectiveness': 0.9,
            'context': {'threat_level': 0.8}
        }
        
        engine.learn_from_feedback(decision_feedback)
        
        # The engine should adapt its decisions based on feedback
        assert engine.learning_history is not None


class TestRLAgent:
    """Test cases for reinforcement learning agent."""
    
    def test_rl_agent_initialization(self):
        """Test RL agent initialization."""
        agent = RLAgent(state_size=10, action_size=3)
        
        assert agent.state_size == 10
        assert agent.action_size == 3
        assert agent.epsilon == 1.0  # Initial exploration rate
    
    def test_action_selection(self):
        """Test action selection."""
        agent = RLAgent(state_size=10, action_size=3)
        
        # Mock state
        state = np.random.rand(10)
        
        action = agent.choose_action(state)
        
        assert 0 <= action < 3
        assert isinstance(action, int)
    
    def test_experience_replay(self):
        """Test experience replay mechanism."""
        agent = RLAgent(state_size=10, action_size=3)
        
        # Mock experiences
        for _ in range(100):
            state = np.random.rand(10)
            action = np.random.randint(0, 3)
            reward = np.random.rand()
            next_state = np.random.rand(10)
            done = False
            
            agent.remember(state, action, reward, next_state, done)
        
        # Train agent
        agent.replay()
        
        assert len(agent.memory) > 0
        assert agent.epsilon < 1.0  # Should decrease after training
    
    def test_reward_calculation(self):
        """Test reward calculation for security actions."""
        agent = RLAgent(state_size=10, action_size=3)
        
        # Mock security outcome
        security_outcome = {
            'threats_blocked': 5,
            'false_positives': 1,
            'response_time': 0.1,
            'user_satisfaction': 0.8
        }
        
        reward = agent.calculate_reward(security_outcome)
        
        assert isinstance(reward, float)
        assert -1 <= reward <= 1  # Normalized reward


class TestRealTimeMonitor:
    """Test cases for real-time monitoring."""
    
    def test_monitor_initialization(self):
        """Test monitor initialization."""
        monitor = RealTimeMonitor()
        
        assert monitor.is_running is False
        assert monitor.alert_threshold == 0.8
        assert len(monitor.metrics) == 0
    
    def test_metric_collection(self):
        """Test metric collection."""
        monitor = RealTimeMonitor()
        
        # Mock system metrics
        metrics = {
            'cpu_usage': 0.75,
            'memory_usage': 0.60,
            'network_traffic': 1024,
            'threat_level': 0.3,
            'encryption_overhead': 0.05
        }
        
        monitor.collect_metrics(metrics)
        
        assert len(monitor.metrics) > 0
        assert 'cpu_usage' in monitor.metrics[-1]
    
    def test_alert_generation(self):
        """Test alert generation."""
        monitor = RealTimeMonitor()
        
        # Mock high threat metrics
        high_threat_metrics = {
            'threat_level': 0.9,
            'attack_attempts': 100,
            'anomaly_score': 0.95
        }
        
        alerts = monitor.generate_alerts(high_threat_metrics)
        
        assert isinstance(alerts, list)
        assert len(alerts) > 0
        assert alerts[0]['severity'] == 'high'
    
    def test_performance_monitoring(self):
        """Test performance monitoring."""
        monitor = RealTimeMonitor()
        
        # Mock performance data
        performance_data = {
            'encryption_time': 0.001,
            'decryption_time': 0.002,
            'key_generation_time': 0.1,
            'throughput': 1000,
            'latency': 0.05
        }
        
        performance_score = monitor.calculate_performance_score(performance_data)
        
        assert 0 <= performance_score <= 1
        assert isinstance(performance_score, float)


if __name__ == "__main__":
    pytest.main([__file__])