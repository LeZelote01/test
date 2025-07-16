"""
Database models using Pydantic for validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from enum import Enum
import uuid

class UserRole(str, Enum):
    """User roles."""
    ADMIN = "admin"
    USER = "user"
    RESEARCHER = "researcher"
    AUDITOR = "auditor"

class ThreatLevel(str, Enum):
    """Threat levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlgorithmType(str, Enum):
    """Cryptographic algorithm types."""
    KYBER = "kyber"
    DILITHIUM = "dilithium"
    RSA = "rsa"
    AES = "aes"
    HYBRID = "hybrid"

class OperationType(str, Enum):
    """Encryption operation types."""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"

class BugBountyStatus(str, Enum):
    """Bug bounty status."""
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FIXED = "fixed"
    PAID = "paid"

class BaseDocument(BaseModel):
    """Base document model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class User(BaseDocument):
    """User model."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password_hash: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.USER
    is_active: bool = True
    is_verified: bool = False
    last_login: Optional[datetime] = None
    preferred_language: str = "en"
    
    # Profile information
    organization: Optional[str] = None
    country: Optional[str] = None
    bio: Optional[str] = None
    
    # Security settings
    two_factor_enabled: bool = False
    api_key: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class EncryptionOperation(BaseDocument):
    """Encryption operation model."""
    user_id: str
    operation_type: OperationType
    algorithm: AlgorithmType
    
    # Input/Output data (encrypted)
    input_data_hash: str
    output_data_hash: str
    
    # Metadata
    key_size: Optional[int] = None
    processing_time: float  # seconds
    success: bool = True
    error_message: Optional[str] = None
    
    # AI decision data
    ai_recommendation: Optional[str] = None
    threat_score: Optional[float] = None
    quantum_resistance_score: Optional[float] = None

class AuditLog(BaseDocument):
    """Audit log model."""
    user_id: Optional[str] = None
    action: str
    resource: str
    details: Dict[str, Any] = Field(default_factory=dict)
    
    # Request information
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Result
    success: bool = True
    error_message: Optional[str] = None

class ThreatDetection(BaseDocument):
    """Threat detection model."""
    threat_type: str
    threat_level: ThreatLevel
    description: str
    
    # Source information
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Detection details
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    detection_method: str  # "ai", "rule", "signature"
    confidence_score: float = Field(ge=0.0, le=1.0)
    
    # Quantum-specific
    quantum_threat: bool = False
    quantum_algorithm_detected: Optional[str] = None
    
    # AI analysis
    ai_analysis: Optional[Dict[str, Any]] = None
    mitigation_suggested: Optional[str] = None
    
    # Response
    blocked: bool = False
    resolved: bool = False
    resolved_at: Optional[datetime] = None

class BugBounty(BaseDocument):
    """Bug bounty model."""
    title: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    category: str  # "crypto", "ai", "blockchain", "general"
    
    # Reporter information
    reporter_id: str
    reporter_name: str
    reporter_email: str
    
    # Technical details
    steps_to_reproduce: List[str]
    proof_of_concept: Optional[str] = None
    affected_components: List[str]
    
    # Status and review
    status: BugBountyStatus = BugBountyStatus.SUBMITTED
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    
    # Reward
    reward_amount: Optional[float] = None
    reward_currency: str = "USD"
    paid_at: Optional[datetime] = None
    
    # Metadata
    public_disclosure: bool = False
    cve_id: Optional[str] = None

class QuantumKey(BaseDocument):
    """Quantum key model."""
    user_id: str
    algorithm: AlgorithmType
    key_type: str  # "public", "private", "shared"
    
    # Key data (encrypted)
    key_data: str
    key_size: int
    
    # Metadata
    purpose: str
    expires_at: Optional[datetime] = None
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    
    # Quantum resistance
    quantum_safe: bool = True
    resistance_level: str  # "high", "medium", "low"

class BlockchainTransaction(BaseDocument):
    """Blockchain transaction model."""
    user_id: str
    transaction_hash: str
    blockchain: str  # "ethereum", "bsc"
    
    # Transaction details
    from_address: str
    to_address: str
    amount: Optional[str] = None
    gas_used: Optional[int] = None
    gas_price: Optional[str] = None
    
    # Status
    status: str = "pending"  # "pending", "confirmed", "failed"
    block_number: Optional[int] = None
    confirmations: int = 0
    
    # Quantum protection
    quantum_protected: bool = False
    protection_method: Optional[str] = None