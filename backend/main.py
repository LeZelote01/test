"""
QuantumGate FastAPI Backend Application.
"""
import os
import logging
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
from dotenv import load_dotenv

from config import settings
from routes import auth, encryption, dashboard
from database.config import init_database
from utils.logger import setup_logger
from utils.security import verify_token

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Setup logging
logger = setup_logger(__name__)

# Security scheme
security = HTTPBearer()

# Database client
db_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_client
    
    # Startup
    logger.info("Starting QuantumGate Backend...")
    
    # Initialize database
    db_client = AsyncIOMotorClient(settings.mongodb_url)
    await init_database(db_client)
    
    # Set database client for routes
    app.state.db = db_client[settings.database_name]
    
    yield
    
    # Shutdown
    logger.info("Shutting down QuantumGate Backend...")
    if db_client:
        db_client.close()

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="Post-Quantum Cryptography Solution with AI-Powered Threat Detection",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user."""
    try:
        token = credentials.credentials
        payload = verify_token(token)
        return payload
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(encryption.router, prefix="/api/encryption", tags=["encryption"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "QuantumGate Backend",
        "version": "1.0.0"
    }

@app.get("/api/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to QuantumGate - Post-Quantum Cryptography Solution",
        "version": "1.0.0",
        "features": [
            "Post-Quantum Cryptography",
            "AI-Powered Threat Detection",
            "Blockchain Integration",
            "Bug Bounty Platform",
            "Multilingual Support"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=settings.debug,
        log_level="info"
    )