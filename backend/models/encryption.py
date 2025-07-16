"""
Encryption models and related classes.
"""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, validator
from database.models import EncryptionOperation, AlgorithmType, OperationType

class EncryptionRequest(BaseModel):
    """Encryption request model."""
    data: str = Field(..., description="Data to encrypt (base64 encoded)")
    algorithm: AlgorithmType = AlgorithmType.HYBRID
    key_size: Optional[int] = None
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    @validator('data')
    def validate_data(cls, v):
        """Validate data is not empty."""
        if not v.strip():
            raise ValueError('Data cannot be empty')
        return v

class DecryptionRequest(BaseModel):
    """Decryption request model."""
    encrypted_data: str = Field(..., description="Encrypted data (base64 encoded)")
    algorithm: AlgorithmType = AlgorithmType.HYBRID
    private_key: Optional[str] = None
    options: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SignatureRequest(BaseModel):
    """Digital signature request model."""
    data: str = Field(..., description="Data to sign (base64 encoded)")
    algorithm: AlgorithmType = AlgorithmType.DILITHIUM
    private_key: Optional[str] = None

class VerificationRequest(BaseModel):
    """Signature verification request model."""
    data: str = Field(..., description="Original data (base64 encoded)")
    signature: str = Field(..., description="Signature to verify (base64 encoded)")
    public_key: str = Field(..., description="Public key for verification (base64 encoded)")
    algorithm: AlgorithmType = AlgorithmType.DILITHIUM

class EncryptionResponse(BaseModel):
    """Encryption response model."""
    operation_id: str
    encrypted_data: str
    algorithm: AlgorithmType
    key_size: Optional[int] = None
    public_key: Optional[str] = None
    processing_time: float
    quantum_resistance_score: Optional[float] = None
    ai_recommendation: Optional[str] = None

class DecryptionResponse(BaseModel):
    """Decryption response model."""
    operation_id: str
    decrypted_data: str
    algorithm: AlgorithmType
    processing_time: float
    success: bool

class SignatureResponse(BaseModel):
    """Digital signature response model."""
    operation_id: str
    signature: str
    algorithm: AlgorithmType
    public_key: str
    processing_time: float

class VerificationResponse(BaseModel):
    """Signature verification response model."""
    operation_id: str
    valid: bool
    algorithm: AlgorithmType
    processing_time: float
    details: Optional[str] = None

class KeyGenerationRequest(BaseModel):
    """Key generation request model."""
    algorithm: AlgorithmType
    key_size: Optional[int] = None
    purpose: str = "general"
    expires_in_days: Optional[int] = None

class KeyGenerationResponse(BaseModel):
    """Key generation response model."""
    key_id: str
    public_key: str
    algorithm: AlgorithmType
    key_size: int
    purpose: str
    expires_at: Optional[datetime] = None
    quantum_safe: bool
    resistance_level: str

class AlgorithmInfoResponse(BaseModel):
    """Algorithm information response model."""
    algorithm: AlgorithmType
    name: str
    description: str
    key_sizes: list
    quantum_resistant: bool
    security_level: str
    performance_rating: str
    use_cases: list

class EncryptionStatsResponse(BaseModel):
    """Encryption statistics response model."""
    total_operations: int
    operations_by_algorithm: Dict[str, int]
    avg_processing_time: float
    quantum_resistant_operations: int
    ai_recommendations_count: int
    threat_detections: int
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

def create_encryption_operation(user_id: str, operation_type: OperationType, 
                               algorithm: AlgorithmType, input_hash: str, 
                               output_hash: str, processing_time: float,
                               success: bool = True, error_message: Optional[str] = None,
                               ai_recommendation: Optional[str] = None,
                               threat_score: Optional[float] = None,
                               quantum_score: Optional[float] = None) -> dict:
    """Create encryption operation dictionary for database insertion."""
    import uuid
    return {
        "id": str(uuid.uuid4()),  # Add UUID for id field
        "user_id": user_id,
        "operation_type": operation_type.value,
        "algorithm": algorithm.value,
        "input_data_hash": input_hash,
        "output_data_hash": output_hash,
        "processing_time": processing_time,
        "success": success,
        "error_message": error_message,
        "ai_recommendation": ai_recommendation,
        "threat_score": threat_score,
        "quantum_resistance_score": quantum_score,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }