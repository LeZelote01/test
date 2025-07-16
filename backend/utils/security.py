"""
Security utilities for QuantumGate.
"""
import hashlib
import hmac
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from config import settings
import logging

logger = logging.getLogger(__name__)

# Password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_secret_key() -> str:
    """Generate a secure secret key."""
    return secrets.token_urlsafe(32)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire})
    
    try:
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise

def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise

def generate_api_key() -> str:
    """Generate a secure API key."""
    return f"qg_{secrets.token_urlsafe(32)}"

def hash_data(data: str) -> str:
    """Hash data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()

def generate_salt() -> str:
    """Generate a random salt."""
    return secrets.token_urlsafe(16)

def secure_hash(data: str, salt: str) -> str:
    """Create a secure hash with salt."""
    return hashlib.pbkdf2_hex(data.encode(), salt.encode(), 100000)

def verify_signature(data: str, signature: str, key: str) -> bool:
    """Verify HMAC signature."""
    try:
        expected_signature = hmac.new(
            key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def create_signature(data: str, key: str) -> str:
    """Create HMAC signature."""
    return hmac.new(
        key.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def encrypt_sensitive_data(data: str, key: Optional[str] = None) -> str:
    """Encrypt sensitive data using Fernet."""
    if key is None:
        key = base64.urlsafe_b64encode(settings.secret_key.encode()[:32])
    
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_sensitive_data(encrypted_data: str, key: Optional[str] = None) -> str:
    """Decrypt sensitive data using Fernet."""
    if key is None:
        key = base64.urlsafe_b64encode(settings.secret_key.encode()[:32])
    
    fernet = Fernet(key)
    decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
    decrypted_data = fernet.decrypt(decoded_data)
    return decrypted_data.decode()

def is_secure_password(password: str) -> bool:
    """Check if password meets security requirements."""
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    return has_upper and has_lower and has_digit and has_special

def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_rate_limited(user_id: str, action: str, limit: int, window: int) -> bool:
    """Check if user is rate limited for an action."""
    # This is a simple implementation
    # In production, you would use Redis or similar
    # For now, we'll return False (not rate limited)
    return False

def log_security_event(event_type: str, user_id: Optional[str] = None, 
                      ip_address: Optional[str] = None, details: Optional[Dict] = None):
    """Log a security event."""
    logger.warning(
        f"Security event: {event_type}",
        extra={
            "security_event": True,
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details or {}
        }
    )

class SecurityValidator:
    """Security validation utilities."""
    
    @staticmethod
    def validate_input(data: str, max_length: int = 1000) -> bool:
        """Validate input data."""
        if not data or len(data) > max_length:
            return False
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            "<script",
            "javascript:",
            "eval(",
            "exec(",
            "DROP TABLE",
            "SELECT * FROM",
            "DELETE FROM"
        ]
        
        data_lower = data.lower()
        return not any(pattern in data_lower for pattern in dangerous_patterns)
    
    @staticmethod
    def sanitize_input(data: str) -> str:
        """Sanitize input data."""
        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", "&", "'", '"', ";", "(", ")", "{", "}"]
        for char in dangerous_chars:
            data = data.replace(char, "")
        
        return data.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None