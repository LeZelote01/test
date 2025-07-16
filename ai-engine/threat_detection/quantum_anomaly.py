"""
Quantum anomaly detection engine for QuantumGate.
Detects quantum computing threats and anomalous patterns.
"""
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import re
import hashlib
import time

logger = logging.getLogger(__name__)

class QuantumAnomalyDetector:
    """Quantum threat and anomaly detection system."""
    
    def __init__(self):
        """Initialize quantum anomaly detector."""
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        
        # Quantum attack signatures
        self.quantum_signatures = self._load_quantum_signatures()
        
        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            "request_frequency": 100,
            "payload_size": 10000,
            "entropy_threshold": 0.8,
            "quantum_pattern_score": 0.6,
            "time_anomaly_score": 0.7
        }
        
        # Training data for baseline
        self.baseline_data = []
        self.is_trained = False
        
        logger.info("Quantum anomaly detector initialized")
    
    def _load_quantum_signatures(self) -> Dict[str, List[str]]:
        """Load quantum attack signatures and patterns."""
        return {
            "shor_algorithm": [
                "factorization",
                "discrete_log",
                "period_finding",
                "quantum_fourier_transform",
                "modular_exponentiation"
            ],
            "grover_algorithm": [
                "search_space",
                "amplitude_amplification",
                "oracle_function",
                "quantum_search",
                "quadratic_speedup"
            ],
            "quantum_cryptanalysis": [
                "quantum_key_recovery",
                "quantum_collision",
                "quantum_preimage",
                "quantum_distinguisher",
                "quantum_differential"
            ],
            "quantum_side_channel": [
                "quantum_timing",
                "quantum_power_analysis",
                "quantum_electromagnetic",
                "quantum_acoustic",
                "quantum_photonic"
            ],
            "post_quantum_attack": [
                "lattice_reduction",
                "code_based_attack",
                "multivariate_attack",
                "isogeny_attack",
                "hash_based_attack"
            ]
        }
    
    def train_baseline(self, training_data: List[Dict[str, Any]]) -> bool:
        """Train baseline model with normal traffic data."""
        try:
            if not training_data:
                logger.warning("No training data provided")
                return False
            
            # Extract features from training data
            features = []
            for data_point in training_data:
                feature_vector = self._extract_features(data_point)
                features.append(feature_vector)
            
            # Convert to numpy array
            X = np.array(features)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train isolation forest
            self.isolation_forest.fit(X_scaled)
            
            # Store baseline data
            self.baseline_data = training_data
            self.is_trained = True
            
            logger.info(f"Baseline model trained with {len(training_data)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Baseline training failed: {e}")
            return False
    
    def detect_quantum_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect quantum anomalies in request data."""
        try:
            start_time = time.time()
            
            # Extract features
            features = self._extract_features(request_data)
            
            # Detect various types of anomalies
            anomaly_results = {
                "quantum_signature_detection": self._detect_quantum_signatures(request_data),
                "statistical_anomaly": self._detect_statistical_anomaly(features),
                "temporal_anomaly": self._detect_temporal_anomaly(request_data),
                "behavioral_anomaly": self._detect_behavioral_anomaly(request_data),
                "entropy_analysis": self._analyze_entropy(request_data),
                "pattern_analysis": self._analyze_patterns(request_data)
            }
            
            # Calculate overall anomaly score
            overall_score = self._calculate_anomaly_score(anomaly_results)
            
            # Determine threat level
            threat_level = self._determine_threat_level(overall_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(anomaly_results, threat_level)
            
            detection_time = time.time() - start_time
            
            result = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_anomaly_score": overall_score,
                "threat_level": threat_level,
                "quantum_threat_detected": overall_score > 0.7,
                "detection_time": detection_time,
                "anomaly_details": anomaly_results,
                "recommendations": recommendations,
                "confidence": self._calculate_confidence(anomaly_results)
            }
            
            if result["quantum_threat_detected"]:
                logger.warning(f"Quantum threat detected with score {overall_score:.3f}")
            
            return result
            
        except Exception as e:
            logger.error(f"Quantum anomaly detection failed: {e}")
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_anomaly_score": 0.0,
                "threat_level": "unknown",
                "quantum_threat_detected": False,
                "error": str(e)
            }
    
    def _extract_features(self, request_data: Dict[str, Any]) -> List[float]:
        """Extract numerical features from request data."""
        features = []
        
        # Request characteristics
        features.append(request_data.get("request_frequency", 0))
        features.append(len(request_data.get("payload", "")))
        features.append(request_data.get("processing_time", 0))
        
        # Payload analysis
        payload = request_data.get("payload", "")
        features.append(self._calculate_entropy(payload))
        features.append(self._count_special_characters(payload))
        features.append(self._calculate_compression_ratio(payload))
        
        # Temporal features
        features.append(datetime.now().hour)
        features.append(datetime.now().weekday())
        features.append(request_data.get("session_duration", 0))
        
        # User behavior features
        features.append(request_data.get("user_requests_per_hour", 0))
        features.append(request_data.get("unique_endpoints_accessed", 0))
        features.append(request_data.get("error_rate", 0))
        
        return features
    
    def _detect_quantum_signatures(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect quantum algorithm signatures in request data."""
        payload = request_data.get("payload", "").lower()
        user_agent = request_data.get("user_agent", "").lower()
        headers = str(request_data.get("headers", {})).lower()
        
        # Combined text for analysis
        combined_text = f"{payload} {user_agent} {headers}"
        
        signature_detections = {}
        total_matches = 0
        
        for signature_type, keywords in self.quantum_signatures.items():
            matches = []
            for keyword in keywords:
                if keyword in combined_text:
                    matches.append(keyword)
                    total_matches += 1
            
            signature_detections[signature_type] = {
                "matches": matches,
                "match_count": len(matches),
                "score": len(matches) / len(keywords)
            }
        
        return {
            "signature_detections": signature_detections,
            "total_matches": total_matches,
            "overall_signature_score": min(total_matches / 20, 1.0)  # Normalize to 0-1
        }
    
    def _detect_statistical_anomaly(self, features: List[float]) -> Dict[str, Any]:
        """Detect statistical anomalies using isolation forest."""
        if not self.is_trained:
            return {
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "reason": "Model not trained"
            }
        
        try:
            # Scale features
            feature_vector = np.array(features).reshape(1, -1)
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict anomaly
            anomaly_prediction = self.isolation_forest.predict(scaled_features)[0]
            anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
            
            # Convert to 0-1 scale
            normalized_score = max(0, min(1, (anomaly_score + 0.5) / 1.0))
            
            return {
                "anomaly_detected": anomaly_prediction == -1,
                "anomaly_score": normalized_score,
                "decision_function_score": anomaly_score,
                "feature_vector": features
            }
            
        except Exception as e:
            logger.error(f"Statistical anomaly detection failed: {e}")
            return {
                "anomaly_detected": False,
                "anomaly_score": 0.0,
                "error": str(e)
            }
    
    def _detect_temporal_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect temporal anomalies in request patterns."""
        current_time = datetime.now()
        
        # Check for unusual timing patterns
        anomalies = []
        score = 0.0
        
        # Check request frequency
        request_frequency = request_data.get("request_frequency", 0)
        if request_frequency > self.anomaly_thresholds["request_frequency"]:
            anomalies.append(f"High request frequency: {request_frequency}")
            score += 0.3
        
        # Check time of day
        if current_time.hour in [0, 1, 2, 3, 4, 5]:  # Late night/early morning
            anomalies.append("Unusual time of day for requests")
            score += 0.2
        
        # Check for burst patterns
        burst_score = request_data.get("burst_pattern_score", 0)
        if burst_score > 0.7:
            anomalies.append("Burst pattern detected")
            score += 0.4
        
        # Check session duration
        session_duration = request_data.get("session_duration", 0)
        if session_duration > 3600:  # > 1 hour
            anomalies.append("Unusually long session")
            score += 0.1
        
        return {
            "temporal_anomalies": anomalies,
            "temporal_score": min(score, 1.0),
            "request_frequency": request_frequency,
            "current_hour": current_time.hour
        }
    
    def _detect_behavioral_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect behavioral anomalies in user patterns."""
        anomalies = []
        score = 0.0
        
        # Check error rate
        error_rate = request_data.get("error_rate", 0)
        if error_rate > 0.3:
            anomalies.append(f"High error rate: {error_rate:.2f}")
            score += 0.3
        
        # Check endpoint diversity
        unique_endpoints = request_data.get("unique_endpoints_accessed", 0)
        total_requests = request_data.get("total_requests", 1)
        endpoint_diversity = unique_endpoints / max(total_requests, 1)
        
        if endpoint_diversity > 0.8:
            anomalies.append("High endpoint diversity - possible scanning")
            score += 0.4
        
        # Check user agent consistency
        user_agent_changes = request_data.get("user_agent_changes", 0)
        if user_agent_changes > 3:
            anomalies.append("Frequent user agent changes")
            score += 0.2
        
        # Check geographic consistency
        location_changes = request_data.get("location_changes", 0)
        if location_changes > 2:
            anomalies.append("Multiple geographic locations")
            score += 0.3
        
        return {
            "behavioral_anomalies": anomalies,
            "behavioral_score": min(score, 1.0),
            "error_rate": error_rate,
            "endpoint_diversity": endpoint_diversity
        }
    
    def _analyze_entropy(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze entropy of request data."""
        payload = request_data.get("payload", "")
        
        if not payload:
            return {
                "entropy_score": 0.0,
                "high_entropy": False,
                "analysis": "No payload data"
            }
        
        # Calculate entropy
        entropy = self._calculate_entropy(payload)
        
        # Analyze entropy patterns
        high_entropy = entropy > self.anomaly_thresholds["entropy_threshold"]
        
        # Additional entropy analysis
        entropy_analysis = {
            "entropy_score": entropy,
            "high_entropy": high_entropy,
            "payload_length": len(payload),
            "unique_characters": len(set(payload)),
            "character_distribution": self._analyze_character_distribution(payload)
        }
        
        return entropy_analysis
    
    def _analyze_patterns(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze patterns in request data."""
        payload = request_data.get("payload", "")
        
        pattern_analysis = {
            "base64_patterns": len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', payload)),
            "hex_patterns": len(re.findall(r'[0-9a-fA-F]{16,}', payload)),
            "crypto_keywords": self._count_crypto_keywords(payload),
            "suspicious_patterns": self._detect_suspicious_patterns(payload),
            "repeated_sequences": self._detect_repeated_sequences(payload)
        }
        
        # Calculate pattern score
        pattern_score = (
            pattern_analysis["base64_patterns"] * 0.2 +
            pattern_analysis["hex_patterns"] * 0.2 +
            pattern_analysis["crypto_keywords"] * 0.3 +
            len(pattern_analysis["suspicious_patterns"]) * 0.2 +
            pattern_analysis["repeated_sequences"] * 0.1
        )
        
        pattern_analysis["pattern_score"] = min(pattern_score / 10, 1.0)
        
        return pattern_analysis
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_length = len(data)
        
        for count in char_counts.values():
            probability = count / data_length
            entropy -= probability * np.log2(probability)
        
        # Normalize to 0-1
        max_entropy = np.log2(min(len(char_counts), 256))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _count_special_characters(self, text: str) -> int:
        """Count special characters in text."""
        special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
        return sum(1 for char in text if char in special_chars)
    
    def _calculate_compression_ratio(self, text: str) -> float:
        """Calculate compression ratio of text."""
        if not text:
            return 0.0
        
        import zlib
        compressed = zlib.compress(text.encode())
        return len(compressed) / len(text)
    
    def _analyze_character_distribution(self, text: str) -> Dict[str, float]:
        """Analyze character distribution in text."""
        if not text:
            return {}
        
        total_chars = len(text)
        char_counts = {}
        
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate percentages
        distribution = {}
        for char, count in char_counts.items():
            distribution[char] = count / total_chars
        
        return distribution
    
    def _count_crypto_keywords(self, text: str) -> int:
        """Count cryptographic keywords in text."""
        crypto_keywords = [
            "encrypt", "decrypt", "cipher", "hash", "signature", "key", "crypto",
            "algorithm", "rsa", "aes", "sha", "md5", "pbkdf2", "hmac", "ecdsa",
            "kyber", "dilithium", "falcon", "sphincs", "ntru", "saber", "frodo"
        ]
        
        text_lower = text.lower()
        return sum(1 for keyword in crypto_keywords if keyword in text_lower)
    
    def _detect_suspicious_patterns(self, text: str) -> List[str]:
        """Detect suspicious patterns in text."""
        suspicious_patterns = []
        
        # SQL injection patterns
        sql_patterns = [
            r"union\s+select",
            r"or\s+1=1",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious_patterns.append(f"SQL injection pattern: {pattern}")
        
        # XSS patterns
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onload=",
            r"onerror="
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious_patterns.append(f"XSS pattern: {pattern}")
        
        # Command injection patterns
        cmd_patterns = [
            r";\s*rm\s+-rf",
            r";\s*cat\s+/etc/passwd",
            r";\s*ls\s+-la",
            r"&&\s*whoami"
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious_patterns.append(f"Command injection pattern: {pattern}")
        
        return suspicious_patterns
    
    def _detect_repeated_sequences(self, text: str) -> int:
        """Detect repeated sequences in text."""
        if len(text) < 10:
            return 0
        
        repeated_count = 0
        for i in range(len(text) - 5):
            sequence = text[i:i+5]
            if text.count(sequence) > 1:
                repeated_count += 1
        
        return repeated_count
    
    def _calculate_anomaly_score(self, anomaly_results: Dict[str, Any]) -> float:
        """Calculate overall anomaly score."""
        weights = {
            "quantum_signature_detection": 0.3,
            "statistical_anomaly": 0.2,
            "temporal_anomaly": 0.15,
            "behavioral_anomaly": 0.15,
            "entropy_analysis": 0.1,
            "pattern_analysis": 0.1
        }
        
        total_score = 0.0
        
        # Quantum signature score
        quantum_score = anomaly_results["quantum_signature_detection"].get("overall_signature_score", 0)
        total_score += quantum_score * weights["quantum_signature_detection"]
        
        # Statistical anomaly score
        statistical_score = anomaly_results["statistical_anomaly"].get("anomaly_score", 0)
        total_score += statistical_score * weights["statistical_anomaly"]
        
        # Temporal anomaly score
        temporal_score = anomaly_results["temporal_anomaly"].get("temporal_score", 0)
        total_score += temporal_score * weights["temporal_anomaly"]
        
        # Behavioral anomaly score
        behavioral_score = anomaly_results["behavioral_anomaly"].get("behavioral_score", 0)
        total_score += behavioral_score * weights["behavioral_anomaly"]
        
        # Entropy score
        entropy_score = anomaly_results["entropy_analysis"].get("entropy_score", 0)
        total_score += entropy_score * weights["entropy_analysis"]
        
        # Pattern score
        pattern_score = anomaly_results["pattern_analysis"].get("pattern_score", 0)
        total_score += pattern_score * weights["pattern_analysis"]
        
        return min(total_score, 1.0)
    
    def _determine_threat_level(self, anomaly_score: float) -> str:
        """Determine threat level based on anomaly score."""
        if anomaly_score >= 0.9:
            return "critical"
        elif anomaly_score >= 0.7:
            return "high"
        elif anomaly_score >= 0.5:
            return "medium"
        elif anomaly_score >= 0.3:
            return "low"
        else:
            return "minimal"
    
    def _generate_recommendations(self, anomaly_results: Dict[str, Any], 
                                threat_level: str) -> List[str]:
        """Generate security recommendations based on anomaly analysis."""
        recommendations = []
        
        if threat_level in ["critical", "high"]:
            recommendations.append("Block request immediately")
            recommendations.append("Escalate to security team")
            recommendations.append("Enable enhanced monitoring")
        
        # Quantum-specific recommendations
        quantum_score = anomaly_results["quantum_signature_detection"].get("overall_signature_score", 0)
        if quantum_score > 0.5:
            recommendations.append("Use post-quantum cryptography")
            recommendations.append("Enable quantum threat monitoring")
            recommendations.append("Review cryptographic implementations")
        
        # Behavioral recommendations
        behavioral_score = anomaly_results["behavioral_anomaly"].get("behavioral_score", 0)
        if behavioral_score > 0.5:
            recommendations.append("Implement rate limiting")
            recommendations.append("Require additional authentication")
            recommendations.append("Monitor user behavior patterns")
        
        # Temporal recommendations
        temporal_score = anomaly_results["temporal_anomaly"].get("temporal_score", 0)
        if temporal_score > 0.5:
            recommendations.append("Implement time-based access controls")
            recommendations.append("Enable burst detection")
            recommendations.append("Review session management")
        
        return recommendations
    
    def _calculate_confidence(self, anomaly_results: Dict[str, Any]) -> float:
        """Calculate confidence in anomaly detection."""
        # Base confidence on number of detection methods that agree
        detections = 0
        total_methods = 0
        
        for method, results in anomaly_results.items():
            total_methods += 1
            if isinstance(results, dict):
                score = results.get("overall_signature_score", 0) or \
                       results.get("anomaly_score", 0) or \
                       results.get("temporal_score", 0) or \
                       results.get("behavioral_score", 0) or \
                       results.get("entropy_score", 0) or \
                       results.get("pattern_score", 0)
                
                if score > 0.5:
                    detections += 1
        
        confidence = detections / total_methods if total_methods > 0 else 0.0
        return min(confidence, 1.0)
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics and model performance."""
        return {
            "model_trained": self.is_trained,
            "training_samples": len(self.baseline_data),
            "detection_thresholds": self.anomaly_thresholds,
            "quantum_signatures": {
                category: len(signatures) 
                for category, signatures in self.quantum_signatures.items()
            },
            "model_parameters": {
                "isolation_forest": {
                    "contamination": self.isolation_forest.contamination,
                    "n_estimators": self.isolation_forest.n_estimators
                },
                "dbscan": {
                    "eps": self.dbscan.eps,
                    "min_samples": self.dbscan.min_samples
                }
            }
        }

# Global instance
quantum_detector = QuantumAnomalyDetector()

# Convenience functions
def detect_quantum_anomaly(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Detect quantum anomalies in request data."""
    return quantum_detector.detect_quantum_anomaly(request_data)

def train_quantum_detector(training_data: List[Dict[str, Any]]) -> bool:
    """Train quantum detector with baseline data."""
    return quantum_detector.train_baseline(training_data)