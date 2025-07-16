"""
AI Decision Service for QuantumGate.
Handles AI-powered threat detection and algorithm selection.
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import openai
import anthropic

from config import settings
from database.models import ThreatLevel, AlgorithmType
from utils.logger import log_operation, log_error

logger = logging.getLogger(__name__)

class AIDecisionService:
    """AI service for threat detection and algorithm selection."""
    
    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        self.threat_model = None
        self.scaler = StandardScaler()
        self.initialize_clients()
        self.initialize_models()
    
    def initialize_clients(self):
        """Initialize AI service clients."""
        try:
            if settings.openai_api_key:
                self.openai_client = openai.OpenAI(api_key=settings.openai_api_key)
                logger.info("OpenAI client initialized")
            
            if settings.anthropic_api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
                logger.info("Anthropic client initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize AI clients: {e}")
    
    def initialize_models(self):
        """Initialize ML models for threat detection."""
        try:
            # Initialize Random Forest model for threat detection
            self.threat_model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight='balanced'
            )
            
            # Train with synthetic data (in production, use real data)
            self._train_threat_model()
            
            logger.info("ML models initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
    
    def _train_threat_model(self):
        """Train the threat detection model with synthetic data."""
        # Generate synthetic training data
        np.random.seed(42)
        
        # Features: [request_frequency, payload_size, encryption_requests, 
        #           quantum_patterns, anomaly_score, time_of_day]
        normal_data = np.random.normal(0, 1, (1000, 6))
        normal_labels = np.zeros(1000)
        
        # Anomalous data
        anomalous_data = np.random.normal(2, 1.5, (200, 6))
        anomalous_labels = np.ones(200)
        
        # Combine data
        X = np.vstack([normal_data, anomalous_data])
        y = np.hstack([normal_labels, anomalous_labels])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.threat_model.fit(X_scaled, y)
        
        logger.info("Threat detection model trained successfully")
    
    async def analyze_request(self, request_data: Dict[str, Any], 
                            user_id: str) -> Dict[str, Any]:
        """Analyze incoming request for threats."""
        try:
            # Extract features from request
            features = self._extract_features(request_data)
            
            # Predict threat level
            threat_prediction = self._predict_threat(features)
            
            # Get AI analysis if available
            ai_analysis = await self._get_ai_analysis(request_data)
            
            # Determine recommended algorithm
            recommended_algorithm = await self._recommend_algorithm(
                request_data, threat_prediction, ai_analysis
            )
            
            log_operation(
                logger, user_id, "threat_analysis",
                {
                    "threat_level": threat_prediction["level"],
                    "confidence": threat_prediction["confidence"],
                    "recommended_algorithm": recommended_algorithm
                }
            )
            
            return {
                "threat_level": threat_prediction["level"],
                "confidence": threat_prediction["confidence"],
                "quantum_threat": threat_prediction["quantum_threat"],
                "recommended_algorithm": recommended_algorithm,
                "ai_analysis": ai_analysis,
                "mitigation_suggestions": threat_prediction["mitigation_suggestions"]
            }
            
        except Exception as e:
            log_error(logger, e, user_id, "threat_analysis")
            return {
                "threat_level": ThreatLevel.MEDIUM,
                "confidence": 0.5,
                "quantum_threat": False,
                "recommended_algorithm": AlgorithmType.HYBRID,
                "ai_analysis": None,
                "mitigation_suggestions": ["Use hybrid encryption as fallback"]
            }
    
    def _extract_features(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from request data for ML analysis."""
        # Extract various features
        features = [
            request_data.get("request_frequency", 0),
            len(request_data.get("payload", "")),
            request_data.get("encryption_requests", 0),
            self._detect_quantum_patterns(request_data),
            self._calculate_anomaly_score(request_data),
            datetime.now().hour  # Time of day
        ]
        
        return np.array(features).reshape(1, -1)
    
    def _detect_quantum_patterns(self, request_data: Dict[str, Any]) -> float:
        """Detect quantum attack patterns in request."""
        # Simple heuristic for quantum pattern detection
        payload = request_data.get("payload", "").lower()
        
        quantum_keywords = [
            "quantum", "shor", "grover", "factoring", "discrete_log",
            "post_quantum", "lattice", "superposition", "entanglement"
        ]
        
        pattern_score = sum(1 for keyword in quantum_keywords if keyword in payload)
        return min(pattern_score / len(quantum_keywords), 1.0)
    
    def _calculate_anomaly_score(self, request_data: Dict[str, Any]) -> float:
        """Calculate anomaly score for request."""
        # Simple anomaly detection based on request characteristics
        payload_size = len(request_data.get("payload", ""))
        request_frequency = request_data.get("request_frequency", 0)
        
        # Anomaly indicators
        size_anomaly = 1 if payload_size > 10000 else 0
        frequency_anomaly = 1 if request_frequency > 100 else 0
        
        return (size_anomaly + frequency_anomaly) / 2
    
    def _predict_threat(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict threat level using ML model."""
        if self.threat_model is None:
            return {
                "level": ThreatLevel.MEDIUM,
                "confidence": 0.5,
                "quantum_threat": False,
                "mitigation_suggestions": ["Model not initialized"]
            }
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.threat_model.predict(features_scaled)[0]
            confidence = self.threat_model.predict_proba(features_scaled)[0].max()
            
            # Determine threat level
            if prediction == 1 and confidence > 0.8:
                threat_level = ThreatLevel.HIGH
            elif prediction == 1 and confidence > 0.6:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            # Check for quantum threat
            quantum_threat = features[0][3] > 0.5  # Quantum pattern score
            
            # Generate mitigation suggestions
            mitigation_suggestions = self._generate_mitigation_suggestions(
                threat_level, quantum_threat, features
            )
            
            return {
                "level": threat_level,
                "confidence": confidence,
                "quantum_threat": quantum_threat,
                "mitigation_suggestions": mitigation_suggestions
            }
            
        except Exception as e:
            logger.error(f"Threat prediction failed: {e}")
            return {
                "level": ThreatLevel.MEDIUM,
                "confidence": 0.5,
                "quantum_threat": False,
                "mitigation_suggestions": ["Error in threat prediction"]
            }
    
    def _generate_mitigation_suggestions(self, threat_level: ThreatLevel, 
                                       quantum_threat: bool, 
                                       features: np.ndarray) -> List[str]:
        """Generate mitigation suggestions based on threat analysis."""
        suggestions = []
        
        if threat_level == ThreatLevel.HIGH:
            suggestions.append("Enable additional authentication")
            suggestions.append("Use maximum encryption strength")
            suggestions.append("Implement rate limiting")
        
        if quantum_threat:
            suggestions.append("Use post-quantum cryptography")
            suggestions.append("Enable quantum threat monitoring")
            suggestions.append("Consider hybrid encryption")
        
        if features[0][1] > 5000:  # Large payload
            suggestions.append("Implement payload size limits")
            suggestions.append("Use chunked encryption")
        
        if features[0][0] > 50:  # High frequency
            suggestions.append("Implement request throttling")
            suggestions.append("Use caching mechanisms")
        
        return suggestions if suggestions else ["No specific mitigations needed"]
    
    async def _get_ai_analysis(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get AI analysis from OpenAI or Anthropic."""
        try:
            analysis = {}
            
            # OpenAI Analysis
            if self.openai_client:
                openai_analysis = await self._get_openai_analysis(request_data)
                analysis["openai"] = openai_analysis
            
            # Anthropic Analysis
            if self.anthropic_client:
                anthropic_analysis = await self._get_anthropic_analysis(request_data)
                analysis["anthropic"] = anthropic_analysis
            
            return analysis if analysis else None
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None
    
    async def _get_openai_analysis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get analysis from OpenAI."""
        try:
            prompt = f"""
            Analyze the following request data for potential security threats:
            
            Request Data: {json.dumps(request_data, indent=2)}
            
            Please provide:
            1. Threat assessment (Low/Medium/High)
            2. Quantum threat probability
            3. Recommended cryptographic algorithm
            4. Security recommendations
            
            Respond in JSON format.
            """
            
            response = await asyncio.to_thread(
                self.openai_client.chat.completions.create,
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500
            )
            
            analysis_text = response.choices[0].message.content
            
            # Try to parse as JSON
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                analysis = {"raw_response": analysis_text}
            
            return analysis
            
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            return {"error": str(e)}
    
    async def _get_anthropic_analysis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get analysis from Anthropic."""
        try:
            prompt = f"""
            Analyze the following request data for potential security threats:
            
            Request Data: {json.dumps(request_data, indent=2)}
            
            Please provide:
            1. Threat assessment (Low/Medium/High)
            2. Quantum threat probability
            3. Recommended cryptographic algorithm
            4. Security recommendations
            
            Respond in JSON format.
            """
            
            response = await asyncio.to_thread(
                self.anthropic_client.messages.create,
                model="claude-3-sonnet-20240229",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            analysis_text = response.content[0].text
            
            # Try to parse as JSON
            try:
                analysis = json.loads(analysis_text)
            except json.JSONDecodeError:
                analysis = {"raw_response": analysis_text}
            
            return analysis
            
        except Exception as e:
            logger.error(f"Anthropic analysis failed: {e}")
            return {"error": str(e)}
    
    async def _recommend_algorithm(self, request_data: Dict[str, Any], 
                                 threat_prediction: Dict[str, Any],
                                 ai_analysis: Optional[Dict[str, Any]]) -> AlgorithmType:
        """Recommend the best algorithm based on analysis."""
        try:
            threat_level = threat_prediction["level"]
            quantum_threat = threat_prediction["quantum_threat"]
            
            # High threat or quantum threat -> use post-quantum
            if threat_level == ThreatLevel.HIGH or quantum_threat:
                return AlgorithmType.KYBER
            
            # Medium threat -> use hybrid
            if threat_level == ThreatLevel.MEDIUM:
                return AlgorithmType.HYBRID
            
            # Low threat -> can use classical
            return AlgorithmType.AES
            
        except Exception as e:
            logger.error(f"Algorithm recommendation failed: {e}")
            return AlgorithmType.HYBRID  # Safe default
    
    async def update_threat_model(self, new_data: List[Dict[str, Any]]) -> bool:
        """Update threat detection model with new data."""
        try:
            if not new_data:
                return False
            
            # Extract features and labels from new data
            features = []
            labels = []
            
            for data_point in new_data:
                feature_vector = self._extract_features(data_point)
                features.append(feature_vector[0])
                labels.append(data_point.get("is_threat", 0))
            
            # Convert to numpy arrays
            X_new = np.array(features)
            y_new = np.array(labels)
            
            # Scale new features
            X_new_scaled = self.scaler.transform(X_new)
            
            # Retrain model (in production, use incremental learning)
            self.threat_model.fit(X_new_scaled, y_new)
            
            logger.info(f"Threat model updated with {len(new_data)} new samples")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update threat model: {e}")
            return False
    
    async def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics."""
        try:
            # This would normally query the database
            # For now, return mock statistics
            return {
                "total_requests_analyzed": 1000,
                "threats_detected": 50,
                "quantum_threats": 5,
                "false_positives": 10,
                "model_accuracy": 0.92,
                "last_updated": datetime.utcnow().isoformat(),
                "threat_distribution": {
                    "low": 900,
                    "medium": 45,
                    "high": 5
                },
                "algorithm_recommendations": {
                    "kyber": 50,
                    "hybrid": 200,
                    "aes": 700,
                    "rsa": 50
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get threat statistics: {e}")
            return {}