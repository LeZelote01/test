"""
Decision engine for QuantumGate threat analysis.
Makes intelligent decisions based on threat analysis results.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
import json

logger = logging.getLogger(__name__)

class ThreatAction(str, Enum):
    """Available threat response actions."""
    ALLOW = "allow"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    BLOCK = "block"
    ESCALATE = "escalate"

class DecisionConfidence(str, Enum):
    """Decision confidence levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

class ThreatDecisionEngine:
    """AI-powered decision engine for threat response."""
    
    def __init__(self):
        """Initialize decision engine."""
        self.decision_rules = self._load_decision_rules()
        self.learning_history = []
        self.false_positive_rate = 0.05  # Target false positive rate
        self.confidence_threshold = 0.7
        
        logger.info("Threat decision engine initialized")
    
    def _load_decision_rules(self) -> Dict[str, Any]:
        """Load decision rules and thresholds."""
        return {
            "threat_level_actions": {
                "minimal": {
                    "action": ThreatAction.ALLOW,
                    "confidence": DecisionConfidence.HIGH,
                    "monitoring": False
                },
                "low": {
                    "action": ThreatAction.MONITOR,
                    "confidence": DecisionConfidence.MEDIUM,
                    "monitoring": True
                },
                "medium": {
                    "action": ThreatAction.RATE_LIMIT,
                    "confidence": DecisionConfidence.MEDIUM,
                    "monitoring": True
                },
                "high": {
                    "action": ThreatAction.CHALLENGE,
                    "confidence": DecisionConfidence.HIGH,
                    "monitoring": True
                },
                "critical": {
                    "action": ThreatAction.BLOCK,
                    "confidence": DecisionConfidence.VERY_HIGH,
                    "monitoring": True
                }
            },
            "quantum_threat_rules": {
                "quantum_threshold": 0.7,
                "quantum_action": ThreatAction.BLOCK,
                "quantum_escalate": True
            },
            "behavioral_rules": {
                "high_frequency_threshold": 100,
                "high_frequency_action": ThreatAction.RATE_LIMIT,
                "suspicious_pattern_threshold": 0.8,
                "suspicious_pattern_action": ThreatAction.CHALLENGE
            },
            "reputation_rules": {
                "bad_reputation_threshold": 0.6,
                "bad_reputation_action": ThreatAction.BLOCK,
                "unknown_reputation_action": ThreatAction.MONITOR
            },
            "override_rules": {
                "whitelist_override": True,
                "emergency_mode": False,
                "manual_override": False
            }
        }
    
    async def make_decision(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Make decision based on threat analysis."""
        try:
            start_time = datetime.utcnow()
            
            # Extract key metrics
            threat_score = threat_analysis.get("overall_threat_score", 0.0)
            threat_level = threat_analysis.get("threat_level", "minimal")
            threat_detected = threat_analysis.get("threat_detected", False)
            threat_indicators = threat_analysis.get("threat_indicators", [])
            
            # Apply decision rules
            decision_result = self._apply_decision_rules(threat_analysis)
            
            # Apply quantum-specific rules
            quantum_decision = self._apply_quantum_rules(threat_analysis)
            if quantum_decision:
                decision_result = self._merge_decisions(decision_result, quantum_decision)
            
            # Apply behavioral rules
            behavioral_decision = self._apply_behavioral_rules(threat_analysis)
            if behavioral_decision:
                decision_result = self._merge_decisions(decision_result, behavioral_decision)
            
            # Apply reputation rules
            reputation_decision = self._apply_reputation_rules(threat_analysis)
            if reputation_decision:
                decision_result = self._merge_decisions(decision_result, reputation_decision)
            
            # Apply override rules
            final_decision = self._apply_overrides(decision_result, threat_analysis)
            
            # Calculate confidence
            confidence = self._calculate_confidence(final_decision, threat_analysis)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(final_decision, threat_analysis)
            
            # Create decision record
            decision_record = {
                "decision_id": f"decision_{int(datetime.utcnow().timestamp() * 1000)}",
                "timestamp": start_time.isoformat(),
                "threat_score": threat_score,
                "threat_level": threat_level,
                "threat_detected": threat_detected,
                "action": final_decision["action"],
                "confidence": confidence,
                "block": final_decision["action"] == ThreatAction.BLOCK,
                "monitor": final_decision.get("monitoring", False),
                "escalate": final_decision.get("escalate", False),
                "reasoning": final_decision.get("reasoning", []),
                "recommendations": recommendations,
                "decision_time": (datetime.utcnow() - start_time).total_seconds()
            }
            
            # Record decision for learning
            self.learning_history.append({
                "decision_record": decision_record,
                "threat_analysis": threat_analysis,
                "timestamp": datetime.utcnow()
            })
            
            # Keep only last 1000 decisions
            if len(self.learning_history) > 1000:
                self.learning_history = self.learning_history[-1000:]
            
            logger.info(f"Decision made: {final_decision['action']} (confidence: {confidence:.3f})")
            
            return decision_record
            
        except Exception as e:
            logger.error(f"Decision making failed: {e}")
            
            # Return safe default decision
            return {
                "decision_id": f"decision_{int(datetime.utcnow().timestamp() * 1000)}",
                "timestamp": datetime.utcnow().isoformat(),
                "threat_score": 0.0,
                "threat_level": "unknown",
                "threat_detected": False,
                "action": ThreatAction.ALLOW,
                "confidence": 0.0,
                "block": False,
                "monitor": True,
                "escalate": False,
                "reasoning": ["Error in decision making - defaulting to allow"],
                "recommendations": ["Review decision engine configuration"],
                "error": str(e)
            }
    
    def _apply_decision_rules(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Apply base decision rules."""
        threat_level = threat_analysis.get("threat_level", "minimal")
        
        # Get base decision from threat level
        base_decision = self.decision_rules["threat_level_actions"].get(threat_level)
        if not base_decision:
            base_decision = self.decision_rules["threat_level_actions"]["minimal"]
        
        return {
            "action": base_decision["action"],
            "confidence": base_decision["confidence"],
            "monitoring": base_decision["monitoring"],
            "escalate": threat_level == "critical",
            "reasoning": [f"Base decision for {threat_level} threat level"]
        }
    
    def _apply_quantum_rules(self, threat_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply quantum-specific decision rules."""
        individual_scores = threat_analysis.get("individual_scores", {})
        quantum_score = individual_scores.get("quantum", 0.0)
        
        quantum_threshold = self.decision_rules["quantum_threat_rules"]["quantum_threshold"]
        
        if quantum_score >= quantum_threshold:
            return {
                "action": self.decision_rules["quantum_threat_rules"]["quantum_action"],
                "confidence": DecisionConfidence.VERY_HIGH,
                "monitoring": True,
                "escalate": self.decision_rules["quantum_threat_rules"]["quantum_escalate"],
                "reasoning": [f"Quantum threat detected (score: {quantum_score:.3f})"]
            }
        
        return None
    
    def _apply_behavioral_rules(self, threat_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply behavioral analysis rules."""
        individual_scores = threat_analysis.get("individual_scores", {})
        behavioral_score = individual_scores.get("behavioral", 0.0)
        
        behavioral_rules = self.decision_rules["behavioral_rules"]
        
        # Check for suspicious patterns
        if behavioral_score >= behavioral_rules["suspicious_pattern_threshold"]:
            return {
                "action": behavioral_rules["suspicious_pattern_action"],
                "confidence": DecisionConfidence.HIGH,
                "monitoring": True,
                "escalate": False,
                "reasoning": [f"Suspicious behavioral pattern (score: {behavioral_score:.3f})"]
            }
        
        return None
    
    def _apply_reputation_rules(self, threat_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Apply reputation-based rules."""
        individual_scores = threat_analysis.get("individual_scores", {})
        reputation_score = individual_scores.get("reputation", 0.0)
        
        reputation_rules = self.decision_rules["reputation_rules"]
        
        # Check for bad reputation
        if reputation_score >= reputation_rules["bad_reputation_threshold"]:
            return {
                "action": reputation_rules["bad_reputation_action"],
                "confidence": DecisionConfidence.HIGH,
                "monitoring": True,
                "escalate": False,
                "reasoning": [f"Bad reputation detected (score: {reputation_score:.3f})"]
            }
        
        return None
    
    def _merge_decisions(self, decision1: Dict[str, Any], decision2: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two decisions, taking the more restrictive action."""
        
        # Action precedence (most restrictive first)
        action_precedence = {
            ThreatAction.BLOCK: 5,
            ThreatAction.ESCALATE: 4,
            ThreatAction.CHALLENGE: 3,
            ThreatAction.RATE_LIMIT: 2,
            ThreatAction.MONITOR: 1,
            ThreatAction.ALLOW: 0
        }
        
        # Choose more restrictive action
        if action_precedence[decision1["action"]] >= action_precedence[decision2["action"]]:
            merged_action = decision1["action"]
        else:
            merged_action = decision2["action"]
        
        # Merge other properties
        merged_decision = {
            "action": merged_action,
            "confidence": max(decision1.get("confidence", DecisionConfidence.LOW), 
                            decision2.get("confidence", DecisionConfidence.LOW)),
            "monitoring": decision1.get("monitoring", False) or decision2.get("monitoring", False),
            "escalate": decision1.get("escalate", False) or decision2.get("escalate", False),
            "reasoning": decision1.get("reasoning", []) + decision2.get("reasoning", [])
        }
        
        return merged_decision
    
    def _apply_overrides(self, decision: Dict[str, Any], threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Apply override rules."""
        override_rules = self.decision_rules["override_rules"]
        
        # Check for emergency mode
        if override_rules.get("emergency_mode", False):
            decision["action"] = ThreatAction.BLOCK
            decision["reasoning"].append("Emergency mode active - blocking all threats")
            return decision
        
        # Check for manual override
        if override_rules.get("manual_override", False):
            decision["action"] = ThreatAction.ALLOW
            decision["reasoning"].append("Manual override active")
            return decision
        
        # Check for whitelist override
        if override_rules.get("whitelist_override", False):
            # In a real implementation, check against whitelist
            # For now, just return original decision
            pass
        
        return decision
    
    def _calculate_confidence(self, decision: Dict[str, Any], threat_analysis: Dict[str, Any]) -> float:
        """Calculate confidence in the decision."""
        base_confidence = {
            DecisionConfidence.LOW: 0.3,
            DecisionConfidence.MEDIUM: 0.6,
            DecisionConfidence.HIGH: 0.8,
            DecisionConfidence.VERY_HIGH: 0.95
        }
        
        confidence = base_confidence.get(decision.get("confidence", DecisionConfidence.LOW), 0.5)
        
        # Adjust based on threat analysis quality
        threat_score = threat_analysis.get("overall_threat_score", 0.0)
        individual_scores = threat_analysis.get("individual_scores", {})
        
        # If multiple detection methods agree, increase confidence
        high_scores = sum(1 for score in individual_scores.values() if score > 0.7)
        if high_scores >= 2:
            confidence += 0.1
        
        # If threat score is very high or very low, increase confidence
        if threat_score > 0.9 or threat_score < 0.1:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _generate_recommendations(self, decision: Dict[str, Any], 
                                threat_analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on decision."""
        recommendations = []
        
        action = decision["action"]
        threat_level = threat_analysis.get("threat_level", "minimal")
        
        if action == ThreatAction.BLOCK:
            recommendations.extend([
                "Block the request immediately",
                "Log the incident for analysis",
                "Consider IP-based blocking"
            ])
        elif action == ThreatAction.CHALLENGE:
            recommendations.extend([
                "Present CAPTCHA or similar challenge",
                "Require additional authentication",
                "Monitor subsequent requests"
            ])
        elif action == ThreatAction.RATE_LIMIT:
            recommendations.extend([
                "Implement rate limiting",
                "Monitor request frequency",
                "Consider temporary IP throttling"
            ])
        elif action == ThreatAction.MONITOR:
            recommendations.extend([
                "Continue monitoring",
                "Log request details",
                "Track behavioral patterns"
            ])
        
        # Add quantum-specific recommendations
        quantum_score = threat_analysis.get("individual_scores", {}).get("quantum", 0.0)
        if quantum_score > 0.5:
            recommendations.extend([
                "Enable post-quantum cryptography",
                "Review quantum-resistant algorithms",
                "Alert security team about quantum threat"
            ])
        
        # Add behavioral recommendations
        behavioral_score = threat_analysis.get("individual_scores", {}).get("behavioral", 0.0)
        if behavioral_score > 0.5:
            recommendations.extend([
                "Analyze user behavior patterns",
                "Consider device fingerprinting",
                "Implement behavioral analytics"
            ])
        
        return recommendations
    
    def learn_from_feedback(self, decision_id: str, feedback: Dict[str, Any]) -> bool:
        """Learn from feedback on previous decisions."""
        try:
            # Find the decision in history
            decision_record = None
            for entry in self.learning_history:
                if entry["decision_record"]["decision_id"] == decision_id:
                    decision_record = entry
                    break
            
            if not decision_record:
                logger.warning(f"Decision {decision_id} not found in history")
                return False
            
            # Process feedback
            was_false_positive = feedback.get("false_positive", False)
            was_false_negative = feedback.get("false_negative", False)
            user_rating = feedback.get("rating", 0)  # 1-5 scale
            
            # Update learning metrics
            if was_false_positive:
                self.false_positive_rate = (self.false_positive_rate * 0.9 + 0.1)
                logger.info(f"False positive reported for decision {decision_id}")
            
            if was_false_negative:
                logger.warning(f"False negative reported for decision {decision_id}")
            
            # Store feedback
            decision_record["feedback"] = feedback
            decision_record["feedback_timestamp"] = datetime.utcnow()
            
            # Adjust thresholds based on feedback
            self._adjust_thresholds(decision_record, feedback)
            
            logger.info(f"Learned from feedback for decision {decision_id}")
            return True
            
        except Exception as e:
            logger.error(f"Learning from feedback failed: {e}")
            return False
    
    def _adjust_thresholds(self, decision_record: Dict[str, Any], feedback: Dict[str, Any]):
        """Adjust decision thresholds based on feedback."""
        # Simple threshold adjustment logic
        # In production, use more sophisticated machine learning
        
        was_false_positive = feedback.get("false_positive", False)
        was_false_negative = feedback.get("false_negative", False)
        
        if was_false_positive:
            # If we blocked something we shouldn't have, raise thresholds slightly
            threat_level = decision_record["decision_record"]["threat_level"]
            if threat_level in self.decision_rules["threat_level_actions"]:
                # Could adjust thresholds here
                pass
        
        if was_false_negative:
            # If we allowed something we shouldn't have, lower thresholds slightly
            threat_level = decision_record["decision_record"]["threat_level"]
            if threat_level in self.decision_rules["threat_level_actions"]:
                # Could adjust thresholds here
                pass
    
    def get_decision_statistics(self) -> Dict[str, Any]:
        """Get decision engine statistics."""
        if not self.learning_history:
            return {
                "total_decisions": 0,
                "action_distribution": {},
                "confidence_distribution": {},
                "feedback_received": 0
            }
        
        total_decisions = len(self.learning_history)
        
        # Action distribution
        action_counts = {}
        confidence_sum = 0.0
        feedback_count = 0
        
        for entry in self.learning_history:
            decision = entry["decision_record"]
            action = decision["action"]
            action_counts[action] = action_counts.get(action, 0) + 1
            confidence_sum += decision.get("confidence", 0.0)
            
            if "feedback" in entry:
                feedback_count += 1
        
        # Calculate distributions
        action_distribution = {
            action: count / total_decisions 
            for action, count in action_counts.items()
        }
        
        return {
            "total_decisions": total_decisions,
            "action_distribution": action_distribution,
            "average_confidence": confidence_sum / total_decisions,
            "feedback_received": feedback_count,
            "false_positive_rate": self.false_positive_rate,
            "decision_rules_count": len(self.decision_rules),
            "history_size": len(self.learning_history)
        }
    
    def export_decision_rules(self) -> str:
        """Export current decision rules."""
        return json.dumps(self.decision_rules, indent=2)
    
    def import_decision_rules(self, rules_json: str) -> bool:
        """Import decision rules from JSON."""
        try:
            imported_rules = json.loads(rules_json)
            
            # Validate rules structure
            required_keys = ["threat_level_actions", "quantum_threat_rules", 
                           "behavioral_rules", "reputation_rules", "override_rules"]
            
            for key in required_keys:
                if key not in imported_rules:
                    logger.error(f"Missing required key in rules: {key}")
                    return False
            
            # Update rules
            self.decision_rules = imported_rules
            logger.info("Decision rules imported successfully")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in rules: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to import rules: {e}")
            return False

# Global instance
decision_engine = ThreatDecisionEngine()

# Convenience functions
async def make_threat_decision(threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Make decision based on threat analysis."""
    return await decision_engine.make_decision(threat_analysis)

def learn_from_decision_feedback(decision_id: str, feedback: Dict[str, Any]) -> bool:
    """Learn from feedback on decision."""
    return decision_engine.learn_from_feedback(decision_id, feedback)

def get_decision_statistics() -> Dict[str, Any]:
    """Get decision engine statistics."""
    return decision_engine.get_decision_statistics()