"""
Algorithm selector for QuantumGate hybrid encryption system.
Automatically selects the best cryptographic algorithm based on context.
"""
import logging
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
import time
from datetime import datetime, timedelta

from ..post_quantum.pq_manager import PostQuantumManager, PQAlgorithm
from ..classical.aes import AESCrypto
from ..classical.rsa import RSACrypto
from .hybrid_encryptor import HybridEncryptor

logger = logging.getLogger(__name__)

class SecurityLevel(str, Enum):
    """Security levels for algorithm selection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"

class ThreatEnvironment(str, Enum):
    """Threat environment types."""
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH_RISK = "high_risk"
    QUANTUM_THREAT = "quantum_threat"

class UseCase(str, Enum):
    """Use cases for algorithm selection."""
    GENERAL = "general"
    COMMUNICATION = "communication"
    STORAGE = "storage"
    AUTHENTICATION = "authentication"
    FINANCIAL = "financial"
    GOVERNMENT = "government"
    RESEARCH = "research"

class AlgorithmSelector:
    """Intelligent algorithm selector for cryptographic operations."""
    
    def __init__(self):
        """Initialize algorithm selector."""
        self.pq_manager = PostQuantumManager()
        self.hybrid_encryptor = HybridEncryptor()
        
        # Algorithm performance cache
        self.performance_cache = {}
        
        # Selection rules
        self.selection_rules = self._load_selection_rules()
        
        # Threat assessment weights
        self.threat_weights = {
            "quantum_threat_probability": 0.3,
            "classical_threat_level": 0.2,
            "performance_requirements": 0.2,
            "security_requirements": 0.3
        }
        
        logger.info("Algorithm selector initialized")
    
    def _load_selection_rules(self) -> Dict[str, Any]:
        """Load algorithm selection rules."""
        return {
            "security_level_mapping": {
                SecurityLevel.LOW: {
                    "algorithms": ["aes", "rsa"],
                    "min_key_size": 128,
                    "quantum_resistance": False
                },
                SecurityLevel.MEDIUM: {
                    "algorithms": ["aes", "rsa", "hybrid"],
                    "min_key_size": 256,
                    "quantum_resistance": False
                },
                SecurityLevel.HIGH: {
                    "algorithms": ["kyber", "dilithium", "hybrid"],
                    "min_key_size": 256,
                    "quantum_resistance": True
                },
                SecurityLevel.MAXIMUM: {
                    "algorithms": ["hybrid"],
                    "min_key_size": 512,
                    "quantum_resistance": True
                }
            },
            "threat_environment_mapping": {
                ThreatEnvironment.NORMAL: {
                    "preferred_algorithms": ["aes", "rsa"],
                    "quantum_resistance_required": False
                },
                ThreatEnvironment.ELEVATED: {
                    "preferred_algorithms": ["hybrid", "kyber"],
                    "quantum_resistance_required": False
                },
                ThreatEnvironment.HIGH_RISK: {
                    "preferred_algorithms": ["kyber", "dilithium"],
                    "quantum_resistance_required": True
                },
                ThreatEnvironment.QUANTUM_THREAT: {
                    "preferred_algorithms": ["hybrid"],
                    "quantum_resistance_required": True
                }
            },
            "use_case_mapping": {
                UseCase.GENERAL: {
                    "recommended_algorithms": ["aes", "hybrid"],
                    "performance_priority": "medium"
                },
                UseCase.COMMUNICATION: {
                    "recommended_algorithms": ["kyber", "hybrid"],
                    "performance_priority": "high"
                },
                UseCase.STORAGE: {
                    "recommended_algorithms": ["aes", "kyber"],
                    "performance_priority": "low"
                },
                UseCase.AUTHENTICATION: {
                    "recommended_algorithms": ["dilithium", "hybrid"],
                    "performance_priority": "high"
                },
                UseCase.FINANCIAL: {
                    "recommended_algorithms": ["hybrid"],
                    "performance_priority": "medium"
                },
                UseCase.GOVERNMENT: {
                    "recommended_algorithms": ["hybrid"],
                    "performance_priority": "low"
                },
                UseCase.RESEARCH: {
                    "recommended_algorithms": ["kyber", "dilithium"],
                    "performance_priority": "low"
                }
            }
        }
    
    def select_algorithm(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Select the best algorithm based on context."""
        try:
            start_time = time.time()
            
            # Parse context
            security_level = SecurityLevel(context.get("security_level", "medium"))
            threat_environment = ThreatEnvironment(context.get("threat_environment", "normal"))
            use_case = UseCase(context.get("use_case", "general"))
            operation_type = context.get("operation_type", "encrypt")  # encrypt, decrypt, sign, verify
            data_size = context.get("data_size", 1024)
            performance_priority = context.get("performance_priority", "medium")
            
            # Assess threat level
            threat_assessment = self._assess_threat_level(context)
            
            # Get candidate algorithms
            candidates = self._get_candidate_algorithms(
                security_level, threat_environment, use_case, operation_type
            )
            
            # Score algorithms
            scored_algorithms = self._score_algorithms(
                candidates, threat_assessment, context
            )
            
            # Select best algorithm
            selected_algorithm = self._select_best_algorithm(scored_algorithms)
            
            selection_time = time.time() - start_time
            
            result = {
                "selected_algorithm": selected_algorithm,
                "alternatives": [alg for alg in scored_algorithms if alg["algorithm"] != selected_algorithm["algorithm"]],
                "threat_assessment": threat_assessment,
                "selection_criteria": {
                    "security_level": security_level.value,
                    "threat_environment": threat_environment.value,
                    "use_case": use_case.value,
                    "operation_type": operation_type,
                    "performance_priority": performance_priority
                },
                "selection_time": selection_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Selected algorithm: {selected_algorithm['algorithm']} (score: {selected_algorithm['score']:.3f})")
            
            return result
            
        except Exception as e:
            logger.error(f"Algorithm selection failed: {e}")
            # Return safe default
            return {
                "selected_algorithm": {
                    "algorithm": "hybrid",
                    "variant": "default",
                    "score": 0.5,
                    "reasoning": "Fallback to hybrid due to selection error"
                },
                "error": str(e)
            }
    
    def _assess_threat_level(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Assess current threat level."""
        threat_indicators = context.get("threat_indicators", {})
        
        # Quantum threat probability
        quantum_threat_prob = threat_indicators.get("quantum_threat_probability", 0.1)
        
        # Classical threat level
        classical_threat_level = threat_indicators.get("classical_threat_level", 0.3)
        
        # Network threat level
        network_threat_level = threat_indicators.get("network_threat_level", 0.2)
        
        # AI-detected anomalies
        ai_anomaly_score = threat_indicators.get("ai_anomaly_score", 0.1)
        
        # Calculate overall threat score
        threat_score = (
            quantum_threat_prob * 0.4 +
            classical_threat_level * 0.3 +
            network_threat_level * 0.2 +
            ai_anomaly_score * 0.1
        )
        
        return {
            "overall_threat_score": threat_score,
            "quantum_threat_probability": quantum_threat_prob,
            "classical_threat_level": classical_threat_level,
            "network_threat_level": network_threat_level,
            "ai_anomaly_score": ai_anomaly_score,
            "threat_level": self._categorize_threat_level(threat_score)
        }
    
    def _categorize_threat_level(self, threat_score: float) -> str:
        """Categorize numerical threat score."""
        if threat_score >= 0.8:
            return "critical"
        elif threat_score >= 0.6:
            return "high"
        elif threat_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _get_candidate_algorithms(self, security_level: SecurityLevel, 
                                 threat_environment: ThreatEnvironment,
                                 use_case: UseCase, operation_type: str) -> List[str]:
        """Get candidate algorithms based on criteria."""
        candidates = set()
        
        # Add algorithms based on security level
        security_rules = self.selection_rules["security_level_mapping"][security_level]
        candidates.update(security_rules["algorithms"])
        
        # Add algorithms based on threat environment
        threat_rules = self.selection_rules["threat_environment_mapping"][threat_environment]
        candidates.update(threat_rules["preferred_algorithms"])
        
        # Add algorithms based on use case
        use_case_rules = self.selection_rules["use_case_mapping"][use_case]
        candidates.update(use_case_rules["recommended_algorithms"])
        
        # Filter by operation type
        if operation_type in ["sign", "verify"]:
            candidates = {alg for alg in candidates if alg in ["dilithium", "rsa", "hybrid"]}
        elif operation_type in ["encrypt", "decrypt"]:
            candidates = {alg for alg in candidates if alg in ["kyber", "aes", "rsa", "hybrid"]}
        
        return list(candidates)
    
    def _score_algorithms(self, candidates: List[str], threat_assessment: Dict[str, Any],
                         context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Score candidate algorithms."""
        scored_algorithms = []
        
        for algorithm in candidates:
            score = self._calculate_algorithm_score(algorithm, threat_assessment, context)
            
            scored_algorithms.append({
                "algorithm": algorithm,
                "variant": self._get_default_variant(algorithm),
                "score": score,
                "reasoning": self._get_selection_reasoning(algorithm, threat_assessment, context)
            })
        
        # Sort by score (descending)
        scored_algorithms.sort(key=lambda x: x["score"], reverse=True)
        
        return scored_algorithms
    
    def _calculate_algorithm_score(self, algorithm: str, threat_assessment: Dict[str, Any],
                                  context: Dict[str, Any]) -> float:
        """Calculate score for an algorithm."""
        score = 0.0
        
        # Security score
        security_score = self._calculate_security_score(algorithm, threat_assessment)
        score += security_score * self.threat_weights["security_requirements"]
        
        # Performance score
        performance_score = self._calculate_performance_score(algorithm, context)
        score += performance_score * self.threat_weights["performance_requirements"]
        
        # Quantum resistance score
        quantum_score = self._calculate_quantum_resistance_score(algorithm, threat_assessment)
        score += quantum_score * self.threat_weights["quantum_threat_probability"]
        
        # Classical threat resistance score
        classical_score = self._calculate_classical_resistance_score(algorithm, threat_assessment)
        score += classical_score * self.threat_weights["classical_threat_level"]
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _calculate_security_score(self, algorithm: str, threat_assessment: Dict[str, Any]) -> float:
        """Calculate security score for algorithm."""
        security_scores = {
            "aes": 0.7,
            "rsa": 0.6,
            "kyber": 0.9,
            "dilithium": 0.9,
            "hybrid": 1.0
        }
        
        base_score = security_scores.get(algorithm, 0.5)
        
        # Adjust based on threat level
        threat_level = threat_assessment.get("threat_level", "low")
        if threat_level == "critical":
            base_score *= 1.2 if algorithm == "hybrid" else 0.8
        elif threat_level == "high":
            base_score *= 1.1 if algorithm in ["hybrid", "kyber", "dilithium"] else 0.9
        
        return min(base_score, 1.0)
    
    def _calculate_performance_score(self, algorithm: str, context: Dict[str, Any]) -> float:
        """Calculate performance score for algorithm."""
        performance_scores = {
            "aes": 1.0,
            "rsa": 0.6,
            "kyber": 0.8,
            "dilithium": 0.9,
            "hybrid": 0.7
        }
        
        base_score = performance_scores.get(algorithm, 0.5)
        
        # Adjust based on data size
        data_size = context.get("data_size", 1024)
        if data_size > 1024 * 1024:  # > 1MB
            if algorithm in ["rsa"]:
                base_score *= 0.5  # RSA is slow for large data
            elif algorithm in ["aes"]:
                base_score *= 1.2  # AES is fast for large data
        
        # Adjust based on performance priority
        performance_priority = context.get("performance_priority", "medium")
        if performance_priority == "high":
            base_score *= 1.2 if algorithm in ["aes", "dilithium"] else 0.8
        elif performance_priority == "low":
            base_score *= 1.1 if algorithm in ["hybrid", "kyber"] else 1.0
        
        return min(base_score, 1.0)
    
    def _calculate_quantum_resistance_score(self, algorithm: str, 
                                          threat_assessment: Dict[str, Any]) -> float:
        """Calculate quantum resistance score."""
        quantum_resistance = {
            "aes": 0.3,  # Partially quantum resistant
            "rsa": 0.0,  # Not quantum resistant
            "kyber": 1.0,  # Fully quantum resistant
            "dilithium": 1.0,  # Fully quantum resistant
            "hybrid": 1.0  # Fully quantum resistant
        }
        
        base_score = quantum_resistance.get(algorithm, 0.0)
        
        # Boost score if quantum threat is detected
        quantum_threat_prob = threat_assessment.get("quantum_threat_probability", 0.1)
        if quantum_threat_prob > 0.5:
            base_score *= 1.5 if base_score > 0.5 else 0.5
        
        return min(base_score, 1.0)
    
    def _calculate_classical_resistance_score(self, algorithm: str,
                                            threat_assessment: Dict[str, Any]) -> float:
        """Calculate classical threat resistance score."""
        classical_resistance = {
            "aes": 0.9,
            "rsa": 0.8,
            "kyber": 0.9,
            "dilithium": 0.9,
            "hybrid": 1.0
        }
        
        return classical_resistance.get(algorithm, 0.5)
    
    def _get_default_variant(self, algorithm: str) -> str:
        """Get default variant for algorithm."""
        default_variants = {
            "aes": "aes256",
            "rsa": "rsa2048",
            "kyber": "kyber1024",
            "dilithium": "dilithium3",
            "hybrid": "hybrid_kyber_rsa"
        }
        
        return default_variants.get(algorithm, "default")
    
    def _get_selection_reasoning(self, algorithm: str, threat_assessment: Dict[str, Any],
                               context: Dict[str, Any]) -> str:
        """Get human-readable reasoning for algorithm selection."""
        reasons = []
        
        # Security reasons
        if algorithm == "hybrid":
            reasons.append("Provides maximum security with quantum resistance")
        elif algorithm in ["kyber", "dilithium"]:
            reasons.append("Post-quantum algorithm provides future-proof security")
        elif algorithm == "aes":
            reasons.append("High performance symmetric encryption")
        elif algorithm == "rsa":
            reasons.append("Widely supported classical algorithm")
        
        # Threat-based reasons
        threat_level = threat_assessment.get("threat_level", "low")
        if threat_level in ["high", "critical"]:
            reasons.append(f"Selected due to {threat_level} threat level")
        
        quantum_threat = threat_assessment.get("quantum_threat_probability", 0.1)
        if quantum_threat > 0.5:
            reasons.append("Quantum threat detected - quantum-resistant algorithm required")
        
        # Performance reasons
        performance_priority = context.get("performance_priority", "medium")
        if performance_priority == "high" and algorithm in ["aes", "dilithium"]:
            reasons.append("Optimized for high performance requirements")
        
        return "; ".join(reasons) if reasons else "Default selection"
    
    def _select_best_algorithm(self, scored_algorithms: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the best algorithm from scored candidates."""
        if not scored_algorithms:
            return {
                "algorithm": "hybrid",
                "variant": "default",
                "score": 0.5,
                "reasoning": "No candidates found - using safe default"
            }
        
        return scored_algorithms[0]
    
    def get_algorithm_recommendations(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get algorithm recommendations with explanations."""
        selection_result = self.select_algorithm(context)
        
        # Get detailed information about selected algorithm
        selected_alg = selection_result["selected_algorithm"]["algorithm"]
        algorithm_info = self._get_algorithm_info(selected_alg)
        
        # Generate recommendations
        recommendations = {
            "primary_recommendation": {
                "algorithm": selected_alg,
                "info": algorithm_info,
                "reasoning": selection_result["selected_algorithm"]["reasoning"]
            },
            "alternative_recommendations": [],
            "security_considerations": self._get_security_considerations(context),
            "performance_considerations": self._get_performance_considerations(context),
            "implementation_notes": self._get_implementation_notes(selected_alg)
        }
        
        # Add alternatives
        for alt in selection_result.get("alternatives", [])[:3]:  # Top 3 alternatives
            alt_info = self._get_algorithm_info(alt["algorithm"])
            recommendations["alternative_recommendations"].append({
                "algorithm": alt["algorithm"],
                "info": alt_info,
                "reasoning": alt["reasoning"],
                "score": alt["score"]
            })
        
        return recommendations
    
    def _get_algorithm_info(self, algorithm: str) -> Dict[str, Any]:
        """Get detailed information about an algorithm."""
        if algorithm == "hybrid":
            return self.hybrid_encryptor.get_hybrid_info()
        elif algorithm in ["kyber", "dilithium"]:
            return self.pq_manager.get_algorithm_info(PQAlgorithm(algorithm))
        else:
            # Basic info for classical algorithms
            return {
                "algorithm": algorithm,
                "type": "classical",
                "quantum_resistant": False,
                "description": f"{algorithm.upper()} classical cryptography algorithm"
            }
    
    def _get_security_considerations(self, context: Dict[str, Any]) -> List[str]:
        """Get security considerations for the context."""
        considerations = []
        
        security_level = context.get("security_level", "medium")
        if security_level in ["high", "maximum"]:
            considerations.append("High security level requires quantum-resistant algorithms")
        
        threat_env = context.get("threat_environment", "normal")
        if threat_env == "quantum_threat":
            considerations.append("Quantum threat detected - use post-quantum cryptography")
        
        use_case = context.get("use_case", "general")
        if use_case in ["financial", "government"]:
            considerations.append("Sensitive use case requires maximum security measures")
        
        return considerations
    
    def _get_performance_considerations(self, context: Dict[str, Any]) -> List[str]:
        """Get performance considerations for the context."""
        considerations = []
        
        data_size = context.get("data_size", 1024)
        if data_size > 1024 * 1024:
            considerations.append("Large data size - consider symmetric encryption")
        
        performance_priority = context.get("performance_priority", "medium")
        if performance_priority == "high":
            considerations.append("High performance requirements - optimize for speed")
        
        return considerations
    
    def _get_implementation_notes(self, algorithm: str) -> List[str]:
        """Get implementation notes for the algorithm."""
        notes = {
            "hybrid": [
                "Combines post-quantum and classical algorithms",
                "Requires more computational resources",
                "Provides maximum security assurance"
            ],
            "kyber": [
                "NIST-approved post-quantum algorithm",
                "Use for key encapsulation",
                "Combine with symmetric encryption for data"
            ],
            "dilithium": [
                "NIST-approved post-quantum signatures",
                "Use for digital signatures only",
                "Larger signature sizes than classical algorithms"
            ],
            "aes": [
                "Use GCM mode for authenticated encryption",
                "Ensure proper key management",
                "Fast for large data encryption"
            ],
            "rsa": [
                "Use at least 2048-bit keys",
                "Not suitable for large data encryption",
                "Consider migration to post-quantum algorithms"
            ]
        }
        
        return notes.get(algorithm, ["Standard implementation guidelines apply"])

# Global instance
algorithm_selector = AlgorithmSelector()

# Convenience functions
def select_algorithm(context: Dict[str, Any]) -> Dict[str, Any]:
    """Select algorithm based on context."""
    return algorithm_selector.select_algorithm(context)

def get_algorithm_recommendations(context: Dict[str, Any]) -> Dict[str, Any]:
    """Get algorithm recommendations."""
    return algorithm_selector.get_algorithm_recommendations(context)