"""
Configuration settings for QuantumGate backend.
"""
import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    mongodb_url: str = Field(default="mongodb://localhost:27017", env="MONGO_URL")
    database_name: str = Field(default="quantumgate", env="DB_NAME")
    
    # Security
    secret_key: str = Field(default="your-secret-key-here", env="SECRET_KEY")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # API Keys
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    
    # Blockchain
    ethereum_rpc_url: Optional[str] = Field(default=None, env="ETHEREUM_RPC_URL")
    bsc_rpc_url: Optional[str] = Field(default=None, env="BSC_RPC_URL")
    private_key: Optional[str] = Field(default=None, env="PRIVATE_KEY")
    
    # Application
    app_name: str = "QuantumGate"
    debug: bool = Field(default=False, env="DEBUG")
    
    # Quantum Cryptography
    kyber_variant: str = "kyber1024"  # Options: kyber512, kyber768, kyber1024
    dilithium_variant: str = "dilithium3"  # Options: dilithium2, dilithium3, dilithium5
    
    # AI Engine
    threat_detection_threshold: float = 0.8
    model_update_interval: int = 3600  # seconds
    
    # Bug Bounty
    bounty_rewards_enabled: bool = True
    min_bounty_amount: float = 100.0
    max_bounty_amount: float = 10000.0
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Global settings instance
settings = Settings()