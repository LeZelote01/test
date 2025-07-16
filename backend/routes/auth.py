"""
Authentication routes for QuantumGate.
"""
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorDatabase
import logging

from models.user import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    PasswordChangeRequest, create_user_dict, hash_password, verify_password
)
from models.audit_log import create_audit_log, AuditActions, AuditResources
from utils.security import create_access_token, verify_token, generate_api_key
from utils.logger import log_operation, log_security_event, log_error
from config import settings

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)

async def get_database() -> AsyncIOMotorDatabase:
    """Get database dependency."""
    from main import app
    return app.state.db

def get_client_ip(request: Request) -> str:
    """Get client IP address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, request: Request, 
                  db: AsyncIOMotorDatabase = Depends(get_database)):
    """Register a new user."""
    try:
        # Check if user already exists
        existing_user = await db.users.find_one({
            "$or": [
                {"email": user_data.email},
                {"username": user_data.username}
            ]
        })
        
        if existing_user:
            if existing_user["email"] == user_data.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )
        
        # Create user
        user_dict = create_user_dict(user_data)
        user_dict["api_key"] = generate_api_key()
        
        # Insert user into database
        result = await db.users.insert_one(user_dict)
        
        # Get created user
        created_user = await db.users.find_one({"_id": result.inserted_id})
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=created_user["id"],
            action=AuditActions.REGISTER,
            resource=AuditResources.USER,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={"username": user_data.username, "email": user_data.email}
        )
        await db.audit_logs.insert_one(audit_log)
        
        # Log security event
        log_security_event(
            logger, "user_registration", 
            user_id=created_user["id"],
            ip_address=get_client_ip(request),
            details={"username": user_data.username}
        )
        
        return UserResponse(**created_user)
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, None, "user_registration")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin, request: Request,
               db: AsyncIOMotorDatabase = Depends(get_database)):
    """Authenticate user and return access token."""
    try:
        # Find user
        user = await db.users.find_one({
            "$or": [
                {"email": user_credentials.username},
                {"username": user_credentials.username}
            ]
        })
        
        if not user:
            log_security_event(
                logger, "login_failed_user_not_found",
                ip_address=get_client_ip(request),
                details={"username": user_credentials.username}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Verify password
        if not verify_password(user_credentials.password, user["password_hash"]):
            log_security_event(
                logger, "login_failed_wrong_password",
                user_id=user["id"],
                ip_address=get_client_ip(request),
                details={"username": user_credentials.username}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if user is active
        if not user.get("is_active", True):
            log_security_event(
                logger, "login_failed_inactive_user",
                user_id=user["id"],
                ip_address=get_client_ip(request)
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user["id"], "username": user["username"]},
            expires_delta=access_token_expires
        )
        
        # Update last login
        await db.users.update_one(
            {"id": user["id"]},
            {"$set": {"last_login": datetime.utcnow(), "updated_at": datetime.utcnow()}}
        )
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user["id"],
            action=AuditActions.LOGIN,
            resource=AuditResources.USER,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={"username": user["username"]}
        )
        await db.audit_logs.insert_one(audit_log)
        
        # Log successful login
        log_security_event(
            logger, "login_successful",
            user_id=user["id"],
            ip_address=get_client_ip(request),
            details={"username": user["username"]},
            level="INFO"
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            user=UserResponse(**user)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, None, "user_login")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security),
                          db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get current user information."""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = await db.users.find_one({"id": user_id})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return UserResponse(**user)
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, None, "get_current_user")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user information"
        )

@router.post("/change-password")
async def change_password(password_data: PasswordChangeRequest, request: Request,
                         credentials: HTTPAuthorizationCredentials = Depends(security),
                         db: AsyncIOMotorDatabase = Depends(get_database)):
    """Change user password."""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = await db.users.find_one({"id": user_id})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Verify current password
        if not verify_password(password_data.current_password, user["password_hash"]):
            log_security_event(
                logger, "password_change_failed_wrong_current",
                user_id=user_id,
                ip_address=get_client_ip(request)
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Hash new password
        new_password_hash = hash_password(password_data.new_password)
        
        # Update password
        await db.users.update_one(
            {"id": user_id},
            {"$set": {
                "password_hash": new_password_hash,
                "updated_at": datetime.utcnow()
            }}
        )
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action=AuditActions.PASSWORD_CHANGE,
            resource=AuditResources.USER,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent")
        )
        await db.audit_logs.insert_one(audit_log)
        
        # Log security event
        log_security_event(
            logger, "password_changed",
            user_id=user_id,
            ip_address=get_client_ip(request),
            level="INFO"
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, user_id, "password_change")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@router.post("/logout")
async def logout(request: Request,
                credentials: HTTPAuthorizationCredentials = Depends(security),
                db: AsyncIOMotorDatabase = Depends(get_database)):
    """Logout user."""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if user_id:
            # Create audit log
            audit_log = create_audit_log(
                user_id=user_id,
                action=AuditActions.LOGOUT,
                resource=AuditResources.USER,
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("User-Agent")
            )
            await db.audit_logs.insert_one(audit_log)
            
            # Log security event
            log_security_event(
                logger, "user_logout",
                user_id=user_id,
                ip_address=get_client_ip(request),
                level="INFO"
            )
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        log_error(logger, e, None, "user_logout")
        return {"message": "Logged out successfully"}

@router.get("/api-key")
async def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security),
                     db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get user's API key."""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = await db.users.find_one({"id": user_id})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return {"api_key": user.get("api_key")}
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, user_id, "get_api_key")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get API key"
        )

@router.post("/regenerate-api-key")
async def regenerate_api_key(request: Request,
                            credentials: HTTPAuthorizationCredentials = Depends(security),
                            db: AsyncIOMotorDatabase = Depends(get_database)):
    """Regenerate user's API key."""
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Generate new API key
        new_api_key = generate_api_key()
        
        # Update user's API key
        await db.users.update_one(
            {"id": user_id},
            {"$set": {
                "api_key": new_api_key,
                "updated_at": datetime.utcnow()
            }}
        )
        
        # Create audit log
        audit_log = create_audit_log(
            user_id=user_id,
            action="api_key_regenerated",
            resource=AuditResources.USER,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent")
        )
        await db.audit_logs.insert_one(audit_log)
        
        # Log security event
        log_security_event(
            logger, "api_key_regenerated",
            user_id=user_id,
            ip_address=get_client_ip(request),
            level="INFO"
        )
        
        return {"api_key": new_api_key}
        
    except HTTPException:
        raise
    except Exception as e:
        log_error(logger, e, user_id, "regenerate_api_key")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate API key"
        )