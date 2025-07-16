"""
Database configuration and initialization.
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import IndexModel, TEXT, ASCENDING, DESCENDING
from config import settings
import logging

logger = logging.getLogger(__name__)

async def init_database(client: AsyncIOMotorClient) -> None:
    """Initialize database with collections and indexes."""
    try:
        db = client[settings.database_name]
        
        # Create collections with indexes
        await create_user_collection(db)
        await create_encryption_collection(db)
        await create_audit_log_collection(db)
        await create_threat_detection_collection(db)
        await create_bug_bounty_collection(db)
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

async def create_user_collection(db: AsyncIOMotorDatabase) -> None:
    """Create users collection with indexes."""
    collection = db.users
    
    # Create indexes
    indexes = [
        IndexModel([("email", ASCENDING)], unique=True),
        IndexModel([("username", ASCENDING)], unique=True),
        IndexModel([("created_at", DESCENDING)]),
        IndexModel([("last_login", DESCENDING)]),
    ]
    
    await collection.create_indexes(indexes)
    logger.info("Users collection created with indexes")

async def create_encryption_collection(db: AsyncIOMotorDatabase) -> None:
    """Create encryption operations collection with indexes."""
    collection = db.encryption_operations
    
    # Create indexes
    indexes = [
        IndexModel([("user_id", ASCENDING)]),
        IndexModel([("operation_type", ASCENDING)]),
        IndexModel([("algorithm", ASCENDING)]),
        IndexModel([("created_at", DESCENDING)]),
        IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)]),
    ]
    
    await collection.create_indexes(indexes)
    logger.info("Encryption operations collection created with indexes")

async def create_audit_log_collection(db: AsyncIOMotorDatabase) -> None:
    """Create audit logs collection with indexes."""
    collection = db.audit_logs
    
    # Create indexes
    indexes = [
        IndexModel([("user_id", ASCENDING)]),
        IndexModel([("action", ASCENDING)]),
        IndexModel([("timestamp", DESCENDING)]),
        IndexModel([("ip_address", ASCENDING)]),
        IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)]),
    ]
    
    await collection.create_indexes(indexes)
    logger.info("Audit logs collection created with indexes")

async def create_threat_detection_collection(db: AsyncIOMotorDatabase) -> None:
    """Create threat detection collection with indexes."""
    collection = db.threat_detections
    
    # Create indexes
    indexes = [
        IndexModel([("threat_level", ASCENDING)]),
        IndexModel([("detected_at", DESCENDING)]),
        IndexModel([("source_ip", ASCENDING)]),
        IndexModel([("user_id", ASCENDING)]),
        IndexModel([("threat_type", ASCENDING)]),
    ]
    
    await collection.create_indexes(indexes)
    logger.info("Threat detection collection created with indexes")

async def create_bug_bounty_collection(db: AsyncIOMotorDatabase) -> None:
    """Create bug bounty collection with indexes."""
    collection = db.bug_bounties
    
    # Create indexes
    indexes = [
        IndexModel([("reporter_id", ASCENDING)]),
        IndexModel([("status", ASCENDING)]),
        IndexModel([("severity", ASCENDING)]),
        IndexModel([("created_at", DESCENDING)]),
        IndexModel([("reward_amount", DESCENDING)]),
    ]
    
    await collection.create_indexes(indexes)
    logger.info("Bug bounty collection created with indexes")

async def get_database() -> AsyncIOMotorDatabase:
    """Get database instance."""
    client = AsyncIOMotorClient(settings.mongodb_url)
    return client[settings.database_name]