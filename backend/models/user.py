"""
User model and related classes.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr, validator
from passlib.context import CryptContext
from database.models import User, UserRole

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    """User creation model."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    preferred_language: str = "en"
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserUpdate(BaseModel):
    """User update model."""
    full_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    bio: Optional[str] = None
    preferred_language: Optional[str] = None

class UserLogin(BaseModel):
    """User login model."""
    username: str
    password: str

class UserResponse(BaseModel):
    """User response model."""
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    preferred_language: str
    organization: Optional[str] = None
    country: Optional[str] = None
    bio: Optional[str] = None
    created_at: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class PasswordChangeRequest(BaseModel):
    """Password change request model."""
    current_password: str
    new_password: str = Field(..., min_length=8)
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def create_user_dict(user_data: UserCreate) -> dict:
    """Create user dictionary for database insertion."""
    import uuid
    user_dict = user_data.dict()
    user_dict['id'] = str(uuid.uuid4())  # Add UUID for id field
    user_dict['password_hash'] = hash_password(user_dict.pop('password'))
    user_dict['role'] = UserRole.USER
    user_dict['is_active'] = True
    user_dict['is_verified'] = False
    user_dict['two_factor_enabled'] = False
    user_dict['created_at'] = datetime.utcnow()
    user_dict['updated_at'] = datetime.utcnow()
    return user_dict