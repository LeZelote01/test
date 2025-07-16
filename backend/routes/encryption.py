"""
Encryption routes for QuantumGate.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
import logging

from models.encryption import (
    EncryptionRequest, DecryptionRequest, SignatureRequest, VerificationRequest,
    EncryptionResponse, DecryptionResponse, SignatureResponse, VerificationResponse,
    KeyGenerationRequest, KeyGenerationResponse, AlgorithmInfoResponse,
    EncryptionStatsResponse, create_encryption_operation
)
from models.audit_log import create_audit_log, AuditActions, AuditResources
from database.models import AlgorithmType, OperationType, ThreatLevel
from services.encryption_service import EncryptionService
from services.ai_decision_service import AIDecisionService
from utils.security import verify_token, hash_data
from utils.logger import log_operation, log_error
from config import settings

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)

# Initialize services
encryption_service = EncryptionService()
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

def get_client_ip(request: Request) -> str:
    """Get client IP address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

@router.post("/encrypt", response_model=EncryptionResponse)
async def encrypt_data(request: Request, encryption_request: EncryptionRequest,
                      user_id: str = Depends(get_current_user_id),
                      db: AsyncIOMotorDatabase = Depends(get_database)):
    """Encrypt data using specified algorithm."""
    try:
        # Analyze request with AI
        request_data = {
            "payload": encryption_request.data,
            "algorithm": encryption_request.algorithm.value,
            "request_frequency": 1,  # This would be tracked in production
            "encryption_requests": 1,
            "user_id": user_id,
            "ip_address": get_client_ip(request)
        }
        
        ai_analysis = await ai_service.analyze_request(request_data, user_id)
        
        # Use AI recommendation if available
        if ai_analysis.get("recommended_algorithm"):
            try:
                recommended_algo = AlgorithmType(ai_analysis["recommended_algorithm"])
                if recommended_algo != encryption_request.algorithm:
                    logger.info(f"AI recommended {recommended_algo.value} instead of {encryption_request.algorithm.value}")
            except ValueError:
                pass  # Invalid algorithm recommendation
        
        # Perform encryption
        result = await encryption_service.encrypt_data(
            data=encryption_request.data,
            algorithm=encryption_request.algorithm,
            user_id=user_id,
            options=encryption_request.options
        )
        
        # Store operation record
        operation_record = create_encryption_operation(
            user_id=user_id,
            operation_type=OperationType.ENCRYPT,
            algorithm=encryption_request.algorithm,
            input_hash=hash_data(encryption_request.data),
            output_hash=hash_data(result["encrypted_data"]),
            processing_time=result["processing_time"],
            success=True,
            ai_recommendation=ai_analysis.get("ai_analysis"),
            threat_score=ai_analysis.get("confidence"),
            quantum_score=result.get("quantum_resistance_score")
        )
        
        await db.encryption_operations.insert_one(operation_record)
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.ENCRYPT,
            resource=AuditResources.ENCRYPTION,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={
                "algorithm": encryption_request.algorithm.value,
                "data_size": len(encryption_request.data),
                "ai_threat_level": ai_analysis.get("threat_level")
            }
        )
        await db.audit_logs.insert_one(audit_log)
        
        # Check for threats
        if ai_analysis.get("threat_level") in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            threat_record = {
                "threat_type": "encryption_request_anomaly",
                "threat_level": ai_analysis["threat_level"],
                "description": f"Suspicious encryption request detected",
                "user_id": user_id,
                "source_ip": get_client_ip(request),
                "detection_method": "ai",
                "confidence_score": ai_analysis.get("confidence", 0.5),
                "quantum_threat": ai_analysis.get("quantum_threat", False),
                "ai_analysis": ai_analysis.get("ai_analysis"),
                "blocked": False,
                "resolved": False
            }
            await db.threat_detections.insert_one(threat_record)
        
        return EncryptionResponse(
            operation_id=operation_record["id"],
            encrypted_data=result["encrypted_data"],
            algorithm=encryption_request.algorithm,
            key_size=result.get("key_size"),
            public_key=result.get("public_key"),
            processing_time=result["processing_time"],
            quantum_resistance_score=result.get("quantum_resistance_score"),
            ai_recommendation=ai_analysis.get("ai_analysis")
        )
        
    except Exception as e:
        log_error(logger, e, user_id, "encrypt_data")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Encryption failed"
        )

@router.post("/decrypt", response_model=DecryptionResponse)
async def decrypt_data(request: Request, decryption_request: DecryptionRequest,
                      user_id: str = Depends(get_current_user_id),
                      db: AsyncIOMotorDatabase = Depends(get_database)):
    """Decrypt data using specified algorithm."""
    try:
        # Perform decryption
        result = await encryption_service.decrypt_data(
            encrypted_data=decryption_request.encrypted_data,
            algorithm=decryption_request.algorithm,
            user_id=user_id,
            private_key=decryption_request.private_key,
            options=decryption_request.options
        )
        
        # Store operation record
        operation_record = create_encryption_operation(
            user_id=user_id,
            operation_type=OperationType.DECRYPT,
            algorithm=decryption_request.algorithm,
            input_hash=hash_data(decryption_request.encrypted_data),
            output_hash=hash_data(result["decrypted_data"]),
            processing_time=result["processing_time"],
            success=result["success"]
        )
        
        await db.encryption_operations.insert_one(operation_record)
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.DECRYPT,
            resource=AuditResources.ENCRYPTION,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={
                "algorithm": decryption_request.algorithm.value,
                "data_size": len(decryption_request.encrypted_data)
            }
        )
        await db.audit_logs.insert_one(audit_log)
        
        return DecryptionResponse(
            operation_id=operation_record["id"],
            decrypted_data=result["decrypted_data"],
            algorithm=decryption_request.algorithm,
            processing_time=result["processing_time"],
            success=result["success"]
        )
        
    except Exception as e:
        log_error(logger, e, user_id, "decrypt_data")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed"
        )

@router.post("/sign", response_model=SignatureResponse)
async def sign_data(request: Request, signature_request: SignatureRequest,
                   user_id: str = Depends(get_current_user_id),
                   db: AsyncIOMotorDatabase = Depends(get_database)):
    """Sign data using specified algorithm."""
    try:
        # Perform signing
        result = await encryption_service.sign_data(
            data=signature_request.data,
            algorithm=signature_request.algorithm,
            user_id=user_id,
            private_key=signature_request.private_key
        )
        
        # Store operation record
        operation_record = create_encryption_operation(
            user_id=user_id,
            operation_type=OperationType.SIGN,
            algorithm=signature_request.algorithm,
            input_hash=hash_data(signature_request.data),
            output_hash=hash_data(result["signature"]),
            processing_time=result["processing_time"],
            success=True
        )
        
        await db.encryption_operations.insert_one(operation_record)
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.SIGN,
            resource=AuditResources.ENCRYPTION,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={
                "algorithm": signature_request.algorithm.value,
                "data_size": len(signature_request.data)
            }
        )
        await db.audit_logs.insert_one(audit_log)
        
        return SignatureResponse(
            operation_id=operation_record["id"],
            signature=result["signature"],
            algorithm=signature_request.algorithm,
            public_key=result["public_key"],
            processing_time=result["processing_time"]
        )
        
    except Exception as e:
        log_error(logger, e, user_id, "sign_data")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signing failed"
        )

@router.post("/verify", response_model=VerificationResponse)
async def verify_signature(request: Request, verification_request: VerificationRequest,
                          user_id: str = Depends(get_current_user_id),
                          db: AsyncIOMotorDatabase = Depends(get_database)):
    """Verify signature using specified algorithm."""
    try:
        # Perform verification
        result = await encryption_service.verify_signature(
            data=verification_request.data,
            signature=verification_request.signature,
            public_key=verification_request.public_key,
            algorithm=verification_request.algorithm,
            user_id=user_id
        )
        
        # Store operation record
        operation_record = create_encryption_operation(
            user_id=user_id,
            operation_type=OperationType.VERIFY,
            algorithm=verification_request.algorithm,
            input_hash=hash_data(verification_request.data),
            output_hash=hash_data(str(result["valid"])),
            processing_time=result["processing_time"],
            success=result["valid"]
        )
        
        await db.encryption_operations.insert_one(operation_record)
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.VERIFY,
            resource=AuditResources.ENCRYPTION,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={
                "algorithm": verification_request.algorithm.value,
                "valid": result["valid"]
            }
        )
        await db.audit_logs.insert_one(audit_log)
        
        return VerificationResponse(
            operation_id=operation_record["id"],
            valid=result["valid"],
            algorithm=verification_request.algorithm,
            processing_time=result["processing_time"],
            details=result.get("details")
        )
        
    except Exception as e:
        log_error(logger, e, user_id, "verify_signature")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verification failed"
        )

@router.post("/generate-keys", response_model=KeyGenerationResponse)
async def generate_keys(request: Request, key_request: KeyGenerationRequest,
                       user_id: str = Depends(get_current_user_id),
                       db: AsyncIOMotorDatabase = Depends(get_database)):
    """Generate cryptographic key pair."""
    try:
        # Generate keys
        result = await encryption_service.generate_key_pair(
            algorithm=key_request.algorithm,
            key_size=key_request.key_size,
            options={"purpose": key_request.purpose}
        )
        
        # Store key record
        key_record = {
            "user_id": user_id,
            "algorithm": key_request.algorithm.value,
            "key_type": "pair",
            "key_data": result["private_key"],  # Store encrypted in production
            "key_size": result["key_size"],
            "purpose": key_request.purpose,
            "expires_at": None,  # Set based on expires_in_days
            "revoked": False,
            "quantum_safe": result["quantum_safe"],
            "resistance_level": result["resistance_level"]
        }
        
        await db.quantum_keys.insert_one(key_record)
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.KEY_GENERATE,
            resource=AuditResources.KEY,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={
                "algorithm": key_request.algorithm.value,
                "key_size": result["key_size"],
                "purpose": key_request.purpose
            }
        )
        await db.audit_logs.insert_one(audit_log)
        
        return KeyGenerationResponse(
            key_id=key_record["id"],
            public_key=result["public_key"],
            algorithm=key_request.algorithm,
            key_size=result["key_size"],
            purpose=key_request.purpose,
            expires_at=key_record.get("expires_at"),
            quantum_safe=result["quantum_safe"],
            resistance_level=result["resistance_level"]
        )
        
    except Exception as e:
        log_error(logger, e, user_id, "generate_keys")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key generation failed"
        )

@router.get("/algorithms", response_model=List[AlgorithmInfoResponse])
async def get_algorithms():
    """Get available cryptographic algorithms."""
    try:
        algorithms = [
            AlgorithmInfoResponse(
                algorithm=AlgorithmType.KYBER,
                name="Kyber",
                description="Post-quantum key encapsulation mechanism",
                key_sizes=[512, 768, 1024],
                quantum_resistant=True,
                security_level="high",
                performance_rating="good",
                use_cases=["secure communication", "data encryption", "quantum-safe messaging"]
            ),
            AlgorithmInfoResponse(
                algorithm=AlgorithmType.DILITHIUM,
                name="Dilithium",
                description="Post-quantum digital signature scheme",
                key_sizes=[2, 3, 5],
                quantum_resistant=True,
                security_level="high",
                performance_rating="excellent",
                use_cases=["document signing", "code signing", "authentication"]
            ),
            AlgorithmInfoResponse(
                algorithm=AlgorithmType.AES,
                name="AES",
                description="Advanced Encryption Standard",
                key_sizes=[128, 192, 256],
                quantum_resistant=False,
                security_level="medium",
                performance_rating="excellent",
                use_cases=["data encryption", "secure storage", "network security"]
            ),
            AlgorithmInfoResponse(
                algorithm=AlgorithmType.RSA,
                name="RSA",
                description="Rivest-Shamir-Adleman public-key cryptosystem",
                key_sizes=[2048, 3072, 4096],
                quantum_resistant=False,
                security_level="medium",
                performance_rating="good",
                use_cases=["digital signatures", "key exchange", "legacy systems"]
            ),
            AlgorithmInfoResponse(
                algorithm=AlgorithmType.HYBRID,
                name="Hybrid",
                description="Combination of post-quantum and classical algorithms",
                key_sizes=[1024, 2048, 4096],
                quantum_resistant=True,
                security_level="very high",
                performance_rating="good",
                use_cases=["maximum security", "transition period", "enterprise applications"]
            )
        ]
        
        return algorithms
        
    except Exception as e:
        logger.error(f"Failed to get algorithms: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get algorithms"
        )

@router.get("/stats", response_model=EncryptionStatsResponse)
async def get_encryption_stats(user_id: str = Depends(get_current_user_id),
                              db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get encryption statistics for the user."""
    try:
        # In production, this would query the database
        # For now, return mock statistics
        stats = EncryptionStatsResponse(
            total_operations=150,
            operations_by_algorithm={
                "kyber": 45,
                "dilithium": 30,
                "aes": 50,
                "rsa": 15,
                "hybrid": 10
            },
            avg_processing_time=0.125,
            quantum_resistant_operations=85,
            ai_recommendations_count=25,
            threat_detections=3
        )
        
        return stats
        
    except Exception as e:
        log_error(logger, e, user_id, "get_encryption_stats")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get encryption statistics"
        )