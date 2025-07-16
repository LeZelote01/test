"""
Threat scanner for QuantumGate.
Combines multiple detection methods for comprehensive threat analysis.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import asyncio
import time

from .quantum_anomaly import QuantumAnomalyDetector
from ..decision_engine.decision_tree import ThreatDecisionEngine
from ..monitoring.real_time_monitor import RealTimeMonitor

logger = logging.getLogger(__name__)

class ThreatScanner:
    """Comprehensive threat scanning system."""
    
    def __init__(self):
        """Initialize threat scanner."""
        self.quantum_detector = QuantumAnomalyDetector()
        self.decision_engine = ThreatDecisionEngine()
        self.real_time_monitor = RealTimeMonitor()
        
        # Scanner configuration
        self.config = {
            "scan_timeout": 30,  # seconds
            "max_concurrent_scans": 10,
            "threat_threshold": 0.7,
            "auto_block_threshold": 0.9
        }
        
        # Active scans tracking
        self.active_scans = {}
        self.scan_history = []
        
        logger.info("Threat scanner initialized")
    
    async def scan_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive threat scan on request."""
        scan_id = f"scan_{int(time.time() * 1000)}"
        start_time = time.time()
        
        try:
            # Track active scan
            self.active_scans[scan_id] = {
                "start_time": start_time,
                "request_data": request_data,
                "status": "running"
            }
            
            # Perform parallel scans
            scan_tasks = [
                self._quantum_scan(request_data),
                self._behavioral_scan(request_data),
                self._pattern_scan(request_data),
                self._reputation_scan(request_data),
                self._ml_scan(request_data)
            ]
            
            # Wait for all scans to complete
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Process results
            quantum_result = scan_results[0] if not isinstance(scan_results[0], Exception) else {}
            behavioral_result = scan_results[1] if not isinstance(scan_results[1], Exception) else {}
            pattern_result = scan_results[2] if not isinstance(scan_results[2], Exception) else {}
            reputation_result = scan_results[3] if not isinstance(scan_results[3], Exception) else {}
            ml_result = scan_results[4] if not isinstance(scan_results[4], Exception) else {}
            
            # Combine results
            combined_result = await self._combine_scan_results(
                quantum_result, behavioral_result, pattern_result, 
                reputation_result, ml_result
            )
            
            # Make decision
            decision = await self.decision_engine.make_decision(combined_result)
            
            scan_time = time.time() - start_time
            
            # Prepare final result
            final_result = {
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "scan_time": scan_time,
                "threat_detected": decision["threat_detected"],
                "threat_level": decision["threat_level"],
                "confidence": decision["confidence"],
                "action_recommended": decision["action"],
                "scan_results": {
                    "quantum_analysis": quantum_result,
                    "behavioral_analysis": behavioral_result,
                    "pattern_analysis": pattern_result,
                    "reputation_analysis": reputation_result,
                    "ml_analysis": ml_result
                },
                "decision_details": decision,
                "blocked": decision.get("block", False)
            }
            
            # Update scan tracking
            self.active_scans[scan_id]["status"] = "completed"
            self.active_scans[scan_id]["result"] = final_result
            
            # Add to history
            self.scan_history.append(final_result)
            
            # Keep only last 1000 scans
            if len(self.scan_history) > 1000:
                self.scan_history = self.scan_history[-1000:]
            
            # Log result
            if final_result["threat_detected"]:
                logger.warning(f"Threat detected: {final_result['threat_level']} (confidence: {final_result['confidence']:.3f})")
            
            return final_result
            
        except Exception as e:
            logger.error(f"Threat scan failed: {e}")
            
            # Clean up active scan
            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "failed"
                self.active_scans[scan_id]["error"] = str(e)
            
            return {
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "scan_time": time.time() - start_time,
                "threat_detected": False,
                "threat_level": "unknown",
                "confidence": 0.0,
                "error": str(e)
            }
        finally:
            # Clean up old active scans
            current_time = time.time()
            expired_scans = [
                sid for sid, scan in self.active_scans.items()
                if current_time - scan["start_time"] > self.config["scan_timeout"]
            ]
            for sid in expired_scans:
                del self.active_scans[sid]
    
    async def _quantum_scan(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform quantum threat scan."""
        try:
            result = self.quantum_detector.detect_quantum_anomaly(request_data)
            return {
                "scan_type": "quantum",
                "threat_score": result.get("overall_anomaly_score", 0),
                "quantum_threat": result.get("quantum_threat_detected", False),
                "details": result
            }
        except Exception as e:
            logger.error(f"Quantum scan failed: {e}")
            return {"scan_type": "quantum", "threat_score": 0, "error": str(e)}
    
    async def _behavioral_scan(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform behavioral analysis scan."""
        try:
            # Analyze request patterns
            behavioral_score = 0.0
            anomalies = []
            
            # Check request frequency
            request_frequency = request_data.get("request_frequency", 0)
            if request_frequency > 100:
                behavioral_score += 0.3
                anomalies.append("High request frequency")
            
            # Check session patterns
            session_duration = request_data.get("session_duration", 0)
            if session_duration > 3600:  # > 1 hour
                behavioral_score += 0.2
                anomalies.append("Long session duration")
            
            # Check error patterns
            error_rate = request_data.get("error_rate", 0)
            if error_rate > 0.5:
                behavioral_score += 0.4
                anomalies.append("High error rate")
            
            # Check geographic patterns
            location_changes = request_data.get("location_changes", 0)
            if location_changes > 3:
                behavioral_score += 0.3
                anomalies.append("Multiple location changes")
            
            return {
                "scan_type": "behavioral",
                "threat_score": min(behavioral_score, 1.0),
                "anomalies": anomalies,
                "behavioral_threat": behavioral_score > 0.5
            }
            
        except Exception as e:
            logger.error(f"Behavioral scan failed: {e}")
            return {"scan_type": "behavioral", "threat_score": 0, "error": str(e)}
    
    async def _pattern_scan(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform pattern analysis scan."""
        try:
            payload = request_data.get("payload", "")
            headers = request_data.get("headers", {})
            
            pattern_score = 0.0
            detected_patterns = []
            
            # Check for malicious patterns
            malicious_patterns = [
                (r"<script.*?>", "XSS attempt"),
                (r"union.*select", "SQL injection"),
                (r"\.\.\/", "Directory traversal"),
                (r"exec\(", "Code execution"),
                (r"eval\(", "Code evaluation"),
                (r"system\(", "System command"),
                (r"wget|curl", "Download attempt"),
                (r"nc\s+-l", "Netcat listener")
            ]
            
            import re
            combined_text = f"{payload} {str(headers)}".lower()
            
            for pattern, description in malicious_patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    pattern_score += 0.2
                    detected_patterns.append(description)
            
            # Check for encoding attempts
            if any(encoding in payload.lower() for encoding in ["base64", "url", "hex"]):
                pattern_score += 0.1
                detected_patterns.append("Encoding detected")
            
            # Check for obfuscation
            if len(set(payload)) / len(payload) < 0.1 and len(payload) > 100:
                pattern_score += 0.3
                detected_patterns.append("Possible obfuscation")
            
            return {
                "scan_type": "pattern",
                "threat_score": min(pattern_score, 1.0),
                "detected_patterns": detected_patterns,
                "pattern_threat": pattern_score > 0.3
            }
            
        except Exception as e:
            logger.error(f"Pattern scan failed: {e}")
            return {"scan_type": "pattern", "threat_score": 0, "error": str(e)}
    
    async def _reputation_scan(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform reputation analysis scan."""
        try:
            ip_address = request_data.get("ip_address", "")
            user_agent = request_data.get("user_agent", "")
            
            reputation_score = 0.0
            reputation_flags = []
            
            # Check IP reputation (simplified)
            if ip_address:
                # Check for known bad IP patterns
                if ip_address.startswith("127.") or ip_address.startswith("192.168."):
                    reputation_score += 0.1
                    reputation_flags.append("Internal IP address")
                
                # Check for Tor exit nodes (simplified check)
                if "tor" in user_agent.lower():
                    reputation_score += 0.4
                    reputation_flags.append("Tor usage detected")
            
            # Check user agent reputation
            if user_agent:
                suspicious_agents = ["curl", "wget", "python", "scanner", "bot"]
                for agent in suspicious_agents:
                    if agent in user_agent.lower():
                        reputation_score += 0.3
                        reputation_flags.append(f"Suspicious user agent: {agent}")
            
            # Check for known attack tools
            attack_tools = ["nmap", "sqlmap", "nikto", "burp", "zap"]
            combined_text = f"{user_agent} {str(request_data.get('headers', {}))}".lower()
            
            for tool in attack_tools:
                if tool in combined_text:
                    reputation_score += 0.5
                    reputation_flags.append(f"Attack tool detected: {tool}")
            
            return {
                "scan_type": "reputation",
                "threat_score": min(reputation_score, 1.0),
                "reputation_flags": reputation_flags,
                "reputation_threat": reputation_score > 0.4
            }
            
        except Exception as e:
            logger.error(f"Reputation scan failed: {e}")
            return {"scan_type": "reputation", "threat_score": 0, "error": str(e)}
    
    async def _ml_scan(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform machine learning based scan."""
        try:
            # Extract features for ML analysis
            features = self._extract_ml_features(request_data)
            
            # Simplified ML scoring (in production, use trained models)
            ml_score = 0.0
            ml_indicators = []
            
            # Payload size analysis
            payload_size = len(request_data.get("payload", ""))
            if payload_size > 10000:
                ml_score += 0.2
                ml_indicators.append("Large payload size")
            
            # Request complexity
            complexity = self._calculate_request_complexity(request_data)
            if complexity > 0.7:
                ml_score += 0.3
                ml_indicators.append("High request complexity")
            
            # Entropy analysis
            entropy = self._calculate_entropy(request_data.get("payload", ""))
            if entropy > 0.8:
                ml_score += 0.2
                ml_indicators.append("High entropy content")
            
            # Timing analysis
            processing_time = request_data.get("processing_time", 0)
            if processing_time > 5.0:
                ml_score += 0.1
                ml_indicators.append("Long processing time")
            
            return {
                "scan_type": "ml",
                "threat_score": min(ml_score, 1.0),
                "ml_indicators": ml_indicators,
                "ml_threat": ml_score > 0.5,
                "features": features
            }
            
        except Exception as e:
            logger.error(f"ML scan failed: {e}")
            return {"scan_type": "ml", "threat_score": 0, "error": str(e)}
    
    def _extract_ml_features(self, request_data: Dict[str, Any]) -> List[float]:
        """Extract features for ML analysis."""
        features = []
        
        # Basic request features
        features.append(len(request_data.get("payload", "")))
        features.append(request_data.get("request_frequency", 0))
        features.append(request_data.get("processing_time", 0))
        features.append(request_data.get("error_rate", 0))
        
        # Content features
        payload = request_data.get("payload", "")
        features.append(self._calculate_entropy(payload))
        features.append(len(set(payload)) / max(len(payload), 1))  # Character diversity
        features.append(payload.count(' ') / max(len(payload), 1))  # Space ratio
        
        # Temporal features
        features.append(datetime.now().hour)
        features.append(datetime.now().weekday())
        features.append(request_data.get("session_duration", 0))
        
        return features
    
    def _calculate_request_complexity(self, request_data: Dict[str, Any]) -> float:
        """Calculate request complexity score."""
        complexity = 0.0
        
        # Payload complexity
        payload = request_data.get("payload", "")
        if payload:
            complexity += len(payload) / 10000  # Normalize by size
            complexity += len(set(payload)) / 256  # Character diversity
        
        # Header complexity
        headers = request_data.get("headers", {})
        complexity += len(headers) / 20  # Number of headers
        
        # Parameter complexity
        params = request_data.get("parameters", {})
        complexity += len(params) / 10  # Number of parameters
        
        return min(complexity, 1.0)
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        import collections
        import math
        
        # Count character frequencies
        counter = collections.Counter(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        
        # Normalize
        max_entropy = math.log2(min(len(counter), 256))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    async def _combine_scan_results(self, quantum_result: Dict[str, Any],
                                   behavioral_result: Dict[str, Any],
                                   pattern_result: Dict[str, Any],
                                   reputation_result: Dict[str, Any],
                                   ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from all scans."""
        
        # Weight different scan types
        weights = {
            "quantum": 0.25,
            "behavioral": 0.2,
            "pattern": 0.25,
            "reputation": 0.15,
            "ml": 0.15
        }
        
        # Calculate weighted score
        total_score = 0.0
        
        total_score += quantum_result.get("threat_score", 0) * weights["quantum"]
        total_score += behavioral_result.get("threat_score", 0) * weights["behavioral"]
        total_score += pattern_result.get("threat_score", 0) * weights["pattern"]
        total_score += reputation_result.get("threat_score", 0) * weights["reputation"]
        total_score += ml_result.get("threat_score", 0) * weights["ml"]
        
        # Determine threat level
        if total_score >= 0.9:
            threat_level = "critical"
        elif total_score >= 0.7:
            threat_level = "high"
        elif total_score >= 0.5:
            threat_level = "medium"
        elif total_score >= 0.3:
            threat_level = "low"
        else:
            threat_level = "minimal"
        
        # Collect all threat indicators
        threat_indicators = []
        
        if quantum_result.get("quantum_threat", False):
            threat_indicators.append("Quantum threat detected")
        
        if behavioral_result.get("behavioral_threat", False):
            threat_indicators.extend(behavioral_result.get("anomalies", []))
        
        if pattern_result.get("pattern_threat", False):
            threat_indicators.extend(pattern_result.get("detected_patterns", []))
        
        if reputation_result.get("reputation_threat", False):
            threat_indicators.extend(reputation_result.get("reputation_flags", []))
        
        if ml_result.get("ml_threat", False):
            threat_indicators.extend(ml_result.get("ml_indicators", []))
        
        return {
            "overall_threat_score": total_score,
            "threat_level": threat_level,
            "threat_detected": total_score > 0.5,
            "threat_indicators": threat_indicators,
            "scan_weights": weights,
            "individual_scores": {
                "quantum": quantum_result.get("threat_score", 0),
                "behavioral": behavioral_result.get("threat_score", 0),
                "pattern": pattern_result.get("threat_score", 0),
                "reputation": reputation_result.get("threat_score", 0),
                "ml": ml_result.get("threat_score", 0)
            }
        }
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        if not self.scan_history:
            return {
                "total_scans": 0,
                "threats_detected": 0,
                "threat_rate": 0.0,
                "average_scan_time": 0.0
            }
        
        total_scans = len(self.scan_history)
        threats_detected = sum(1 for scan in self.scan_history if scan.get("threat_detected", False))
        
        # Calculate averages
        avg_scan_time = sum(scan.get("scan_time", 0) for scan in self.scan_history) / total_scans
        avg_threat_score = sum(scan.get("decision_details", {}).get("threat_score", 0) for scan in self.scan_history) / total_scans
        
        # Threat level distribution
        threat_levels = {}
        for scan in self.scan_history:
            level = scan.get("threat_level", "unknown")
            threat_levels[level] = threat_levels.get(level, 0) + 1
        
        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "threat_rate": threats_detected / total_scans,
            "average_scan_time": avg_scan_time,
            "average_threat_score": avg_threat_score,
            "threat_level_distribution": threat_levels,
            "active_scans": len(self.active_scans),
            "scan_history_size": len(self.scan_history)
        }

# Global instance
threat_scanner = ThreatScanner()

# Convenience functions
async def scan_threat(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Scan for threats in request data."""
    return await threat_scanner.scan_request(request_data)

def get_threat_statistics() -> Dict[str, Any]:
    """Get threat scanning statistics."""
    return threat_scanner.get_scan_statistics()