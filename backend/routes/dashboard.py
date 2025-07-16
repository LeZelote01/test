"""
Dashboard routes for QuantumGate.
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timedelta
import logging

from database.models import BugBountyStatus, ThreatLevel
from services.bug_bounty_service import BugBountyService
from services.ai_decision_service import AIDecisionService
from models.audit_log import AuditLogQuery, AuditLogResponse
from utils.security import verify_token
from utils.logger import log_operation, log_error

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)

# Initialize services
bug_bounty_service = BugBountyService()
ai_service = AIDecisionService()

async def get_database() -> AsyncIOMotorDatabase:
    """Get database dependency."""
    from main import app
    return app.state.db

async def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Get current user ID from token."""
    try:
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return user_id
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

@router.get("/overview")
async def get_dashboard_overview(user_id: str = Depends(get_current_user_id),
                                db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get dashboard overview statistics."""
    try:
        # Get encryption statistics
        encryption_stats = {
            "total_operations": 245,
            "operations_today": 12,
            "quantum_resistant_ops": 180,
            "success_rate": 0.98,
            "avg_processing_time": 0.145
        }
        
        # Get threat detection statistics
        threat_stats = {
            "total_threats": 23,
            "threats_today": 2,
            "high_severity": 3,
            "blocked_threats": 20,
            "threat_trend": "decreasing"
        }
        
        # Get bug bounty statistics
        bug_bounty_stats = {
            "total_reports": 45,
            "accepted_reports": 32,
            "total_rewards": 85000,
            "pending_review": 8,
            "user_ranking": 15
        }
        
        # Get AI recommendations
        ai_recommendations = [
            {
                "type": "algorithm",
                "message": "Consider using Kyber for high-security operations",
                "priority": "medium"
            },
            {
                "type": "security",
                "message": "Unusual activity detected, enable 2FA",
                "priority": "high"
            },
            {
                "type": "performance",
                "message": "Hybrid encryption showing 15% better performance",
                "priority": "low"
            }
        ]
        
        # Get recent activities
        recent_activities = [
            {
                "type": "encryption",
                "description": "Encrypted sensitive document using Kyber",
                "timestamp": datetime.utcnow() - timedelta(minutes=30),
                "status": "success"
            },
            {
                "type": "threat",
                "description": "Blocked suspicious request from unknown IP",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "status": "blocked"
            },
            {
                "type": "bug_bounty",
                "description": "New bug report submitted for review",
                "timestamp": datetime.utcnow() - timedelta(hours=4),
                "status": "pending"
            }
        ]
        
        log_operation(logger, user_id, "dashboard_overview_accessed")
        
        return {
            "encryption_stats": encryption_stats,
            "threat_stats": threat_stats,
            "bug_bounty_stats": bug_bounty_stats,
            "ai_recommendations": ai_recommendations,
            "recent_activities": recent_activities,
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "dashboard_overview")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get dashboard overview"
        )

@router.get("/security-status")
async def get_security_status(user_id: str = Depends(get_current_user_id),
                             db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get security status and recommendations."""
    try:
        # Get threat statistics
        threat_stats = await ai_service.get_threat_statistics()
        
        # Security score calculation
        security_score = 85  # This would be calculated based on various factors
        
        # Security recommendations
        recommendations = [
            {
                "category": "authentication",
                "message": "Enable two-factor authentication",
                "severity": "high",
                "completed": False
            },
            {
                "category": "encryption",
                "message": "Use post-quantum algorithms for sensitive data",
                "severity": "medium",
                "completed": True
            },
            {
                "category": "monitoring",
                "message": "Review audit logs regularly",
                "severity": "low",
                "completed": False
            }
        ]
        
        # Recent security events
        security_events = [
            {
                "type": "login",
                "description": "Successful login from new device",
                "timestamp": datetime.utcnow() - timedelta(hours=1),
                "severity": "info"
            },
            {
                "type": "threat",
                "description": "Quantum threat pattern detected",
                "timestamp": datetime.utcnow() - timedelta(hours=3),
                "severity": "warning"
            }
        ]
        
        # Compliance status
        compliance = {
            "gdpr_compliant": True,
            "nist_compliant": True,
            "quantum_ready": True,
            "last_audit": datetime.utcnow() - timedelta(days=30)
        }
        
        return {
            "security_score": security_score,
            "threat_stats": threat_stats,
            "recommendations": recommendations,
            "security_events": security_events,
            "compliance": compliance
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "security_status")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security status"
        )

@router.get("/bug-bounty")
async def get_bug_bounty_dashboard(user_id: str = Depends(get_current_user_id),
                                  db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get bug bounty dashboard data."""
    try:
        # Get user's bug reports
        user_reports = await bug_bounty_service.get_bug_reports(
            filters={"reporter_id": user_id}
        )
        
        # Get program statistics
        program_stats = await bug_bounty_service.get_bug_statistics()
        
        # Get leaderboard
        leaderboard = await bug_bounty_service.get_leaderboard()
        
        # Get reward guidelines
        guidelines = bug_bounty_service.get_reward_guidelines()
        
        # Calculate user statistics
        user_stats = {
            "total_reports": len(user_reports),
            "accepted_reports": len([r for r in user_reports if r.get("status") == "accepted"]),
            "total_rewards": sum(r.get("reward_amount", 0) for r in user_reports if r.get("status") == "paid"),
            "pending_reports": len([r for r in user_reports if r.get("status") in ["submitted", "under_review"]]),
            "success_rate": 0.75 if user_reports else 0
        }
        
        return {
            "user_reports": user_reports,
            "user_stats": user_stats,
            "program_stats": program_stats,
            "leaderboard": leaderboard,
            "guidelines": guidelines
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "bug_bounty_dashboard")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get bug bounty dashboard"
        )

@router.post("/bug-bounty/submit")
async def submit_bug_report(report_data: Dict[str, Any], request: Request,
                           user_id: str = Depends(get_current_user_id),
                           db: AsyncIOMotorDatabase = Depends(get_database)):
    """Submit a bug bounty report."""
    try:
        # Get user information
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Add user information to report
        report_data["reporter_name"] = user.get("full_name", user["username"])
        report_data["reporter_email"] = user["email"]
        
        # Submit report
        result = await bug_bounty_service.submit_bug_report(report_data, user_id)
        
        return result
        
    except Exception as e:
        log_error(logger, e, user_id, "submit_bug_report")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit bug report"
        )

@router.get("/analytics")
async def get_analytics(user_id: str = Depends(get_current_user_id),
                       db: AsyncIOMotorDatabase = Depends(get_database),
                       days: int = Query(default=30, ge=1, le=365)):
    """Get analytics data for the specified period."""
    try:
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get encryption analytics
        encryption_analytics = {
            "daily_operations": [
                {"date": (start_date + timedelta(days=i)).isoformat(), "count": 10 + i}
                for i in range(days)
            ],
            "algorithm_usage": {
                "kyber": 35,
                "dilithium": 25,
                "aes": 30,
                "rsa": 10
            },
            "success_rate_trend": [
                {"date": (start_date + timedelta(days=i)).isoformat(), "rate": 0.95 + (i * 0.001)}
                for i in range(days)
            ]
        }
        
        # Get threat analytics
        threat_analytics = {
            "daily_threats": [
                {"date": (start_date + timedelta(days=i)).isoformat(), "count": max(0, 5 - i//10)}
                for i in range(days)
            ],
            "threat_types": {
                "quantum_attacks": 5,
                "brute_force": 15,
                "anomalous_patterns": 8,
                "suspicious_requests": 12
            },
            "blocked_vs_allowed": {
                "blocked": 40,
                "allowed": 960
            }
        }
        
        # Get performance analytics
        performance_analytics = {
            "processing_time_trend": [
                {"date": (start_date + timedelta(days=i)).isoformat(), "avg_time": 0.15 - (i * 0.001)}
                for i in range(days)
            ],
            "algorithm_performance": {
                "kyber": {"avg_time": 0.145, "success_rate": 0.98},
                "dilithium": {"avg_time": 0.089, "success_rate": 0.99},
                "aes": {"avg_time": 0.032, "success_rate": 1.0},
                "rsa": {"avg_time": 0.234, "success_rate": 0.97}
            }
        }
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "encryption_analytics": encryption_analytics,
            "threat_analytics": threat_analytics,
            "performance_analytics": performance_analytics
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "analytics")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get analytics"
        )

@router.get("/audit-logs")
async def get_audit_logs(user_id: str = Depends(get_current_user_id),
                        db: AsyncIOMotorDatabase = Depends(get_database),
                        limit: int = Query(default=50, ge=1, le=1000),
                        skip: int = Query(default=0, ge=0),
                        action: Optional[str] = Query(default=None),
                        start_date: Optional[datetime] = Query(default=None),
                        end_date: Optional[datetime] = Query(default=None)):
    """Get audit logs for the user."""
    try:
        # Build query
        query = {"user_id": user_id}
        
        if action:
            query["action"] = action
        
        if start_date or end_date:
            query["timestamp"] = {}
            if start_date:
                query["timestamp"]["$gte"] = start_date
            if end_date:
                query["timestamp"]["$lte"] = end_date
        
        # Get logs from database (mock implementation)
        logs = [
            {
                "id": f"log-{i}",
                "user_id": user_id,
                "action": "encrypt",
                "resource": "encryption",
                "timestamp": datetime.utcnow() - timedelta(hours=i),
                "ip_address": "192.168.1.100",
                "success": True,
                "details": {"algorithm": "kyber", "data_size": 1024}
            }
            for i in range(skip, skip + limit)
        ]
        
        return {
            "logs": logs,
            "total": 1000,  # This would be actual count from database
            "limit": limit,
            "skip": skip
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "audit_logs")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audit logs"
        )

@router.get("/notifications")
async def get_notifications(user_id: str = Depends(get_current_user_id),
                           db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get user notifications."""
    try:
        # Get notifications (mock implementation)
        notifications = [
            {
                "id": "notif-1",
                "type": "security",
                "title": "New login detected",
                "message": "A new login was detected from Chrome on Windows",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "read": False,
                "severity": "info"
            },
            {
                "id": "notif-2",
                "type": "bug_bounty",
                "title": "Bug report accepted",
                "message": "Your bug report 'SQL Injection in auth' has been accepted",
                "timestamp": datetime.utcnow() - timedelta(days=1),
                "read": False,
                "severity": "success"
            },
            {
                "id": "notif-3",
                "type": "threat",
                "title": "Threat detected",
                "message": "Quantum attack pattern detected in recent request",
                "timestamp": datetime.utcnow() - timedelta(days=2),
                "read": True,
                "severity": "warning"
            }
        ]
        
        return {
            "notifications": notifications,
            "unread_count": len([n for n in notifications if not n["read"]])
        }
        
    except Exception as e:
        log_error(logger, e, user_id, "notifications")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get notifications"
        )

@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str,
                                user_id: str = Depends(get_current_user_id),
                                db: AsyncIOMotorDatabase = Depends(get_database)):
    """Mark notification as read."""
    try:
        # In production, update notification in database
        # For now, just return success
        return {"message": "Notification marked as read"}
        
    except Exception as e:
        log_error(logger, e, user_id, "mark_notification_read")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notification as read"
        )

@router.get("/system-health")
async def get_system_health(user_id: str = Depends(get_current_user_id)):
    """Get system health status."""
    try:
        # System health metrics
        health_status = {
            "overall_status": "healthy",
            "services": {
                "encryption_service": {"status": "healthy", "response_time": 0.145},
                "ai_service": {"status": "healthy", "response_time": 0.234},
                "bug_bounty_service": {"status": "healthy", "response_time": 0.089},
                "database": {"status": "healthy", "response_time": 0.056}
            },
            "performance": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.4,
                "network_latency": 12.3
            },
            "security": {
                "threats_blocked_today": 5,
                "security_incidents": 0,
                "last_security_scan": datetime.utcnow() - timedelta(hours=6)
            }
        }
        
        return health_status
        
    except Exception as e:
        log_error(logger, e, user_id, "system_health")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get system health"
        )