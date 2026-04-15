# logging_config.py
# Enterprise-Grade Logging Configuration for SentinelsVault
# 
# This module implements professional logging with:
#   - Rotating file handlers (prevents infinite log growth)
#   - Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
#   - Separate logs for security events and system events
#   - Log formatting with timestamps, module names, and line numbers
#   - Console output for development, file output for production

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

LOG_DIR = "logs"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB per log file
BACKUP_COUNT = 10  # Keep 10 backup files

# Ensure log directory exists
Path(LOG_DIR).mkdir(exist_ok=True)


class CustomFormatter(logging.Formatter):
    """
    Custom log formatter with color support for console output.
    Uses ANSI color codes for better readability in terminal.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        # Add color to level name for console output
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(log_level=logging.INFO, console_output=True):
    """
    Configure enterprise-grade logging for SentinelsVault.
    
    Creates three log files:
        1. sentinels_vault.log - All logs (rotating)
        2. security_events.log - Security-specific events (authentication, encryption)
        3. errors.log - Only errors and critical issues
    
    Args:
        log_level: Logging level (default: INFO)
        console_output: Whether to output logs to console
    
    Returns:
        logger: Root logger instance
    """
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-20s | Line: %(lineno)-4d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    security_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # ─────────────────────────────────────────────
    # 1. MAIN LOG FILE (Rotating)
    # ─────────────────────────────────────────────
    main_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(LOG_DIR, 'sentinels_vault.log'),
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    main_handler.setLevel(log_level)
    main_handler.setFormatter(detailed_formatter)
    
    # ─────────────────────────────────────────────
    # 2. SECURITY EVENTS LOG (Separate file)
    # ─────────────────────────────────────────────
    security_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(LOG_DIR, 'security_events.log'),
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(security_formatter)
    
    # Add a filter to only log security-related events
    class SecurityFilter(logging.Filter):
        def filter(self, record):
            security_keywords = ['auth', 'login', 'encrypt', 'decrypt', 'key', 
                                 'password', 'mfa', 'recovery', 'vault', 'lock']
            return any(keyword in record.getMessage().lower() for keyword in security_keywords)
    
    security_handler.addFilter(SecurityFilter())
    
    # ─────────────────────────────────────────────
    # 3. ERRORS ONLY LOG
    # ─────────────────────────────────────────────
    error_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(LOG_DIR, 'errors.log'),
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    
    # ─────────────────────────────────────────────
    # 4. CONSOLE HANDLER (Optional)
    # ─────────────────────────────────────────────
    handlers = [main_handler, security_handler, error_handler]
    
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(CustomFormatter(simple_formatter._fmt))
        handlers.append(console_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers
    )
    
    # Suppress noisy third-party loggers
    logging.getLogger('customtkinter').setLevel(logging.WARNING)
    logging.getLogger('PIL').setLevel(logging.WARNING)
    logging.getLogger('cryptography').setLevel(logging.WARNING)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info(f"SentinelsVault logging initialized at {datetime.now()}")
    logger.info(f"Log directory: {os.path.abspath(LOG_DIR)}")
    logger.info(f"Log level: {logging.getLevelName(log_level)}")
    logger.info("=" * 60)
    
    return logger


def log_security_event(event_type, user_action, status, details=""):
    """
    Helper function to log security events consistently.
    
    Args:
        event_type: e.g., 'AUTH', 'ENCRYPT', 'DECRYPT', 'MFA', 'RECOVERY'
        user_action: e.g., 'LOGIN_ATTEMPT', 'PASSWORD_VIEW', 'VAULT_LOCK'
        status: 'SUCCESS', 'FAILURE', 'WARNING'
        details: Additional information about the event
    """
    logger = logging.getLogger('security')
    
    log_message = f"[{event_type}] {user_action} - {status}"
    if details:
        log_message += f" | {details}"
    
    if status == 'FAILURE':
        logger.warning(log_message)
    elif status == 'SUCCESS':
        logger.info(log_message)
    else:
        logger.warning(log_message)


# ─────────────────────────────────────────────
# CUSTOM EXCEPTIONS (Professional error types)
# ─────────────────────────────────────────────

class VaultError(Exception):
    """Base exception for all vault-related errors."""
    pass


class AuthenticationError(VaultError):
    """Raised when master password verification fails."""
    pass


class EncryptionError(VaultError):
    """Raised when encryption/decryption operations fail."""
    pass


class DatabaseError(VaultError):
    """Raised when database operations fail."""
    pass


class IntegrityError(VaultError):
    """Raised when data integrity check fails (tampering detected)."""
    pass


class VaultLockedError(VaultError):
    """Raised when trying to access locked vault."""
    pass


class MFADisabledError(VaultError):
    """Raised when MFA is required but not set up."""
    pass


class RecoveryCodeError(VaultError):
    """Raised when recovery code verification fails."""
    pass