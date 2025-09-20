"""
Logging Utility Module
Configures logging for the honeypot interceptor
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Dict

def setup_logging(config: Dict):
    """Setup logging configuration"""
    try:
        # Get configuration
        log_level = config.get('level', 'INFO')
        log_file = config.get('file', 'honeypot_interceptor.log')
        max_size = config.get('max_size', '10MB')
        backup_count = config.get('backup_count', 5)
        
        # Convert log level
        level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Create logs directory
        log_path = Path(log_file)
        log_path.parent.mkdir(exist_ok=True)
        
        # Convert max_size to bytes
        size_bytes = _parse_size(max_size)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=size_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Set specific logger levels
        logging.getLogger('scapy').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        
        logging.info("Logging configured successfully")
        
    except Exception as e:
        print(f"Error setting up logging: {e}")

def _parse_size(size_str: str) -> int:
    """Parse size string to bytes"""
    size_str = size_str.upper()
    
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        return int(size_str)
