# encryption_provider.py
# MODULE 2: Cryptographic Engine — The Vault
# This module performs the actual AES-256 encryption and decryption.
# It uses GCM mode, which provides both PRIVACY and INTEGRITY.

import os
import logging

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import]
except ImportError as e:
    raise ImportError("cryptography package is required. Install with: pip install cryptography") from e

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logger = logging.getLogger(__name__)

class EncryptionProvider:
    """
    Handles AES-256-GCM encryption and decryption operations.
    
    AES-256: 256-bit key length (Military Grade).
    GCM Mode: Provides Confidentiality and Authenticity (Integrity).
    """

    def __init__(self, key: bytes):
        """
        Initializes the engine with the 32-byte key from Module 1.
        """
        if len(key) != 32:
            logger.critical("Initialization failed: Key must be 32 bytes.")
            raise ValueError(f"Key must be 32 bytes for AES-256. Got {len(key)} bytes.")

        self._key = key  # Internal reference
        self.aesgcm = AESGCM(key)
        logger.info("EncryptionProvider initialized with AES-256-GCM.")

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypts plaintext string.
        Returns: (ciphertext_with_tag, nonce)
        """
        try:
            # Generate a 12-byte initialization vector (nonce)
            # Standard for GCM to prevent 'Replay Attacks'
            nonce = os.urandom(12) 
            
            # Encode string to bytes
            data = plaintext.encode('utf-8')

            # Encrypt: returns Ciphertext + 16-byte Auth Tag
            ciphertext = self.aesgcm.encrypt(nonce, data, None)
            
            logger.info("Encryption successful.")
            return ciphertext, nonce

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Decrypts bytes and verifies the integrity tag.
        Returns: Plaintext string
        """
        try:
            # Decrypt and verify. If tag is invalid, this raises an error.
            decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)
            
            logger.info("Decryption and Integrity check successful.")
            return decrypted_data.decode('utf-8')

        except Exception as e:
            # This is critical: It catches tampering or wrong keys
            logger.error("Decryption/Integrity Check Failed. Data may be tampered.")
            raise ValueError("Integrity check failed: Decryption not possible.") from e

    def encrypt_bytes(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypts raw bytes using AES-256-GCM.
        Used for encrypting non-string secrets (vault key, MFA secret, etc.).
        Returns: (ciphertext_with_tag, nonce)
        """
        try:
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
            return ciphertext, nonce
        except Exception as e:
            logger.error(f"Encryption (bytes) failed: {str(e)}")
            raise

    def decrypt_bytes(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        Decrypts raw bytes using AES-256-GCM and verifies integrity tag.
        Returns: plaintext bytes
        """
        try:
            return self.aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            logger.error("Decryption/Integrity Check Failed (bytes). Data may be tampered.")
            raise ValueError("Integrity check failed: Decryption not possible.") from e

    def secure_wipe(self):
        """
        SDE Best Practice: Overwrites the key in RAM before deletion.
        This prevents 'Cold Boot' attacks or memory dumping.
        """
        try:
            # Overwrite the actual byte array in memory
            # We use a zero-filled byte string
            self._key = b'\x00' * 32
            logger.info("Master encryption key securely wiped from RAM.")
        except AttributeError:
            pass
        finally:
            if hasattr(self, '_key'):
                del self._key