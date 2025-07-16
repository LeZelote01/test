"""
Audit log models and related classes.
"""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from database.models import AuditLog

class AuditLogCreate(BaseModel):
    """Audit log creation model."""
    action: str
    resource: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None

class AuditLogResponse(BaseModel):
    """Audit log response model."""
    id: str
    user_id: Optional[str] = None
    action: str
    resource: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class AuditLogQuery(BaseModel):
    """Audit log query model."""
    user_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    success: Optional[bool] = None
    limit: int = Field(default=100, ge=1, le=1000)
    skip: int = Field(default=0, ge=0)

class AuditLogStats(BaseModel):
    """Audit log statistics model."""
    total_logs: int
    successful_actions: int
    failed_actions: int
    unique_users: int
    unique_actions: int
    most_common_actions: Dict[str, int]
    actions_by_hour: Dict[str, int]
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

def create_audit_log(user_id: Optional[str], action: str, resource: str,
                    details: Dict[str, Any] = None, ip_address: Optional[str] = None,
                    user_agent: Optional[str] = None, success: bool = True,
                    error_message: Optional[str] = None) -> dict:
    """Create audit log dictionary for database insertion."""
    return {
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "details": details or {},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": datetime.utcnow(),
        "success": success,
        "error_message": error_message,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }

# Common audit actions
class AuditActions:
    """Common audit actions."""
    LOGIN = "login"
    LOGOUT = "logout"
    REGISTER = "register"
    PASSWORD_CHANGE = "password_change"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    KEY_GENERATE = "key_generate"
    KEY_REVOKE = "key_revoke"
    THREAT_DETECT = "threat_detect"
    BUG_REPORT = "bug_report"
    BLOCKCHAIN_TRANSACTION = "blockchain_transaction"
    ADMIN_ACTION = "admin_action"
    API_ACCESS = "api_access"
    PROFILE_UPDATE = "profile_update"
    SETTINGS_CHANGE = "settings_change"

# Common audit resources
class AuditResources:
    """Common audit resources."""
    USER = "user"
    ENCRYPTION = "encryption"
    KEY = "key"
    THREAT = "threat"
    BUG_BOUNTY = "bug_bounty"
    BLOCKCHAIN = "blockchain"
    ADMIN = "admin"
    API = "api"
    PROFILE = "profile"
    SETTINGS = "settings"