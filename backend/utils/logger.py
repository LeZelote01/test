"""
Logging utilities for QuantumGate.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import json

class QuantumGateFormatter(logging.Formatter):
    """Custom formatter for QuantumGate logs."""
    
    def format(self, record):
        """Format log record."""
        # Add timestamp
        record.timestamp = datetime.utcnow().isoformat()
        
        # Add service name
        record.service = "quantumgate"
        
        # Create structured log format
        log_entry = {
            "timestamp": record.timestamp,
            "service": record.service,
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_entry["user_id"] = record.user_id
        if hasattr(record, 'operation_id'):
            log_entry["operation_id"] = record.operation_id
        if hasattr(record, 'request_id'):
            log_entry["request_id"] = record.request_id
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)

def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Setup logger with custom formatting."""
    logger = logging.getLogger(name)
    
    # Don't add handlers if already configured
    if logger.handlers:
        return logger
    
    # Set level
    logger.setLevel(getattr(logging, level.upper()))
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    # Create formatter
    formatter = QuantumGateFormatter()
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    return logger

def log_operation(logger: logging.Logger, user_id: str, operation: str, 
                 details: Optional[dict] = None, level: str = "INFO") -> None:
    """Log an operation with user context."""
    extra = {
        "user_id": user_id,
        "operation": operation,
        "details": details or {}
    }
    
    message = f"Operation: {operation}"
    if details:
        message += f" - Details: {details}"
    
    logger.log(getattr(logging, level.upper()), message, extra=extra)

def log_security_event(logger: logging.Logger, event_type: str, 
                      user_id: Optional[str] = None, ip_address: Optional[str] = None,
                      details: Optional[dict] = None, level: str = "WARNING") -> None:
    """Log a security event."""
    extra = {
        "event_type": event_type,
        "security_event": True
    }
    
    if user_id:
        extra["user_id"] = user_id
    if ip_address:
        extra["ip_address"] = ip_address
    if details:
        extra["details"] = details
    
    message = f"Security Event: {event_type}"
    if details:
        message += f" - Details: {details}"
    
    logger.log(getattr(logging, level.upper()), message, extra=extra)

def log_performance(logger: logging.Logger, operation: str, duration: float,
                   user_id: Optional[str] = None, details: Optional[dict] = None) -> None:
    """Log performance metrics."""
    extra = {
        "operation": operation,
        "duration": duration,
        "performance_log": True
    }
    
    if user_id:
        extra["user_id"] = user_id
    if details:
        extra["details"] = details
    
    message = f"Performance: {operation} took {duration:.3f}s"
    
    logger.info(message, extra=extra)

def log_error(logger: logging.Logger, error: Exception, 
             user_id: Optional[str] = None, operation: Optional[str] = None,
             details: Optional[dict] = None) -> None:
    """Log an error with context."""
    extra = {
        "error_type": type(error).__name__,
        "error_message": str(error)
    }
    
    if user_id:
        extra["user_id"] = user_id
    if operation:
        extra["operation"] = operation
    if details:
        extra["details"] = details
    
    message = f"Error in {operation or 'unknown operation'}: {str(error)}"
    
    logger.error(message, extra=extra, exc_info=True)

# Create default logger
default_logger = setup_logger("quantumgate")