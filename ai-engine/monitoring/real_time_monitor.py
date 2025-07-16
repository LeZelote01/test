"""
Real-time monitoring system for QuantumGate.
"""
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import deque
import time
import json

logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """Real-time monitoring and alerting system."""
    
    def __init__(self):
        """Initialize real-time monitor."""
        self.active_sessions = {}
        self.metrics_buffer = deque(maxlen=10000)
        self.alert_callbacks = []
        self.monitoring_active = False
        self.monitor_task = None
        
        # Monitoring thresholds
        self.thresholds = {
            "requests_per_second": 100,
            "error_rate": 0.1,
            "response_time": 5.0,
            "threat_rate": 0.05,
            "quantum_threats": 1
        }
        
        logger.info("Real-time monitor initialized")
    
    async def start_monitoring(self):
        """Start real-time monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Real-time monitoring started")
    
    async def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.monitoring_active = False
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Real-time monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                
                # Check thresholds
                alerts = self._check_thresholds(metrics)
                
                # Send alerts
                for alert in alerts:
                    await self._send_alert(alert)
                
                # Store metrics
                self.metrics_buffer.append({
                    "timestamp": datetime.utcnow(),
                    "metrics": metrics,
                    "alerts": alerts
                })
                
                # Wait before next check
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "active_sessions": len(self.active_sessions),
            "requests_per_second": self._calculate_rps(),
            "error_rate": self._calculate_error_rate(),
            "response_time": self._calculate_avg_response_time(),
            "threat_rate": self._calculate_threat_rate(),
            "quantum_threats": self._count_quantum_threats(),
            "memory_usage": self._get_memory_usage(),
            "cpu_usage": self._get_cpu_usage()
        }
    
    def _calculate_rps(self) -> float:
        """Calculate requests per second."""
        # Simplified calculation
        return len(self.active_sessions) / 60  # Rough estimate
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate."""
        # Simplified calculation
        return 0.02  # 2% error rate
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time."""
        # Simplified calculation
        return 0.150  # 150ms average
    
    def _calculate_threat_rate(self) -> float:
        """Calculate threat detection rate."""
        # Simplified calculation
        return 0.01  # 1% threat rate
    
    def _count_quantum_threats(self) -> int:
        """Count quantum threats in recent period."""
        # Simplified calculation
        return 0
    
    def _get_memory_usage(self) -> float:
        """Get memory usage percentage."""
        # Simplified - would use psutil in production
        return 45.2
    
    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage."""
        # Simplified - would use psutil in production
        return 23.8
    
    def _check_thresholds(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check metrics against thresholds."""
        alerts = []
        
        for metric, threshold in self.thresholds.items():
            if metric in metrics:
                value = metrics[metric]
                
                if value > threshold:
                    alerts.append({
                        "type": "threshold_exceeded",
                        "metric": metric,
                        "value": value,
                        "threshold": threshold,
                        "severity": self._get_alert_severity(metric, value, threshold),
                        "timestamp": datetime.utcnow().isoformat()
                    })
        
        return alerts
    
    def _get_alert_severity(self, metric: str, value: float, threshold: float) -> str:
        """Get alert severity based on how much threshold is exceeded."""
        ratio = value / threshold
        
        if ratio > 3.0:
            return "critical"
        elif ratio > 2.0:
            return "high"
        elif ratio > 1.5:
            return "medium"
        else:
            return "low"
    
    async def _send_alert(self, alert: Dict[str, Any]):
        """Send alert to registered callbacks."""
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def register_alert_callback(self, callback: Callable):
        """Register alert callback function."""
        self.alert_callbacks.append(callback)
    
    def record_request(self, request_data: Dict[str, Any]):
        """Record a request for monitoring."""
        session_id = request_data.get("session_id", "anonymous")
        
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {
                "start_time": datetime.utcnow(),
                "request_count": 0,
                "error_count": 0,
                "threat_count": 0
            }
        
        session = self.active_sessions[session_id]
        session["request_count"] += 1
        session["last_request"] = datetime.utcnow()
        
        # Record threat if detected
        if request_data.get("threat_detected", False):
            session["threat_count"] += 1
        
        # Record error if present
        if request_data.get("error", False):
            session["error_count"] += 1
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        return self._collect_metrics()
    
    def get_metrics_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get metrics history for specified time period."""
        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        history = []
        for entry in self.metrics_buffer:
            if entry["timestamp"] >= cutoff_time:
                history.append(entry)
        
        return history
    
    def get_active_sessions(self) -> Dict[str, Any]:
        """Get information about active sessions."""
        return {
            "total_sessions": len(self.active_sessions),
            "sessions": dict(list(self.active_sessions.items())[:10])  # Top 10
        }

# Global instance
real_time_monitor = RealTimeMonitor()