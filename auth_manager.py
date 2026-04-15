# auth_manager.py
# MODULE 1: Authentication & Key Derivation — The Gatekeeper
# This is the first line of defense in SentinelsVault.
# It handles two jobs:
#   1. Hashing the Master Password using Argon2id (for verification)
#   2. Deriving the AES-256 encryption key using PBKDF2 (for the vault)

import os
import hashlib
import logging
import secrets

try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore
except ImportError as e:
    raise ImportError(
        "argon2-cffi is required. Install it with: pip install argon2-cffi"
    ) from e

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
# __name__ means this logger is named "auth_manager"
# All logs from this file go to vault.log automatically
# because main.py configured logging globally.
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000   # OWASP 2024 recommended minimum
SALT_SIZE         = 32        # 32 bytes = 256-bit salt
KEY_SIZE          = 32        # 32 bytes = 256-bit AES key

class AuthManager:
    """
    The Gatekeeper of SentinelsVault.

    Uses a dual-layer approach:
    ─────────────────────────────────────────
    Layer 1 — Argon2id:
        Used to VERIFY the master password on login.
        Argon2id is memory-hard (uses 64MB RAM to compute),
        making GPU brute-force attacks extremely expensive.
        Winner of the 2015 Password Hashing Competition.

    Layer 2 — PBKDF2 (SHA-256):
        Used to DERIVE the 256-bit AES encryption key.
        Runs 600,000 iterations — even if an attacker
        gets the salt, guessing the password requires
        600,000 hash computations per attempt.
    ─────────────────────────────────────────
    """

    def __init__(self):
        """
        Initializes the Argon2id hasher with enterprise-grade parameters.

        time_cost=2     → Runs 2 iterations of Argon2id internally
        memory_cost=65536 → Uses 64MB of RAM per hash computation
                            This is what makes GPU attacks impractical
        parallelism=2   → Uses 2 CPU threads
        hash_len=32     → Output hash is 32 bytes (256 bits)
        """
        self.ph = PasswordHasher(
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
            hash_len=32
        )
        logger.info("AuthManager initialized with Argon2id configuration.")

    def generate_salt(self) -> bytes:
        """
        Generates a cryptographically random 32-byte salt.

        What is a salt?
        A salt is random noise added to a password before hashing.
        It ensures that even if two users have the SAME password,
        their stored hashes look COMPLETELY DIFFERENT.
        This defeats Rainbow Table attacks.

        os.urandom() uses the operating system's secure
        random number generator — much stronger than random().

        Returns: 32 random bytes (e.g., b'\\x3a\\xf2\\x91...')
        """
        salt = os.urandom(SALT_SIZE)
        logger.info(f"Generated {SALT_SIZE}-byte cryptographic salt.")
        return salt

    def hash_master_password_argon2(self, password: str) -> str:
        """
        Hashes the master password using Argon2id.
        This hash is stored in the database during vault setup.
        It is used later to VERIFY the password — not to encrypt.

        Why store a hash and not the password?
        Because hashing is ONE-WAY. Even if someone steals the
        database, they cannot reverse the hash to get the password.

        Returns: An Argon2id hash string like:
        '$argon2id$v=19$m=65536,t=2,p=2$...$...'
        """
        hashed = self.ph.hash(password)
        logger.info("Master password hashed with Argon2id successfully.")
        return hashed

    def verify_master_password_argon2(self, stored_hash: str, entered_password: str) -> bool:
        """
        Verifies the entered password against the stored Argon2id hash.
        Called every time the user tries to log into the vault.

        stored_hash:      The Argon2id hash saved in DB during setup
        entered_password: What the user just typed on the login screen

        Returns: True if password is correct, False if wrong.

        The VerifyMismatchError is raised by argon2-cffi when
        the password does not match — we catch it and return False
        instead of crashing the application.
        """
        try:
            result = self.ph.verify(stored_hash, entered_password)
            logger.info("Master password verification successful.")
            return result
        except VerifyMismatchError:
            # Wrong password entered — this is expected, not a crash
            logger.warning("Master password verification failed — wrong password.")
            return False
        except Exception as e:
            # Unexpected error (corrupted hash, etc.)
            logger.error(f"Unexpected error during password verification: {e}")
            return False

    def derive_key_pbkdf2(self, password: str, salt: bytes) -> bytes:
        """
        Derives the 256-bit AES encryption key from the master password.
        Uses PBKDF2-HMAC-SHA256 with 600,000 iterations.

        How it works:
        1. Takes the plain text password (e.g., 'MySecret@123')
        2. Combines it with the stored salt
        3. Runs SHA-256 hashing 600,000 times in a loop
        4. Output: a unique 32-byte (256-bit) key

        Why 600,000 iterations?
        Each login attempt requires 600,000 hashes.
        An attacker trying to guess passwords must also
        run 600,000 hashes per guess — making brute-force
        attacks billions of times slower.

        This key is NEVER saved to disk.
        It lives only in RAM and is wiped when the vault locks.

        Returns: 32 raw bytes used directly as the AES-256 key
        """
        key = hashlib.pbkdf2_hmac(
            'sha256',                         # Hash algorithm inside the loop
            password.encode('utf-8'),          # Convert string to bytes
            salt,                              # The random salt from the database
            PBKDF2_ITERATIONS,                 # 600,000 iterations
            dklen=KEY_SIZE                     # Output = 32 bytes = 256 bits
        )
        logger.info(f"PBKDF2 key derivation complete ({PBKDF2_ITERATIONS} iterations).")
        return key

    def generate_recovery_code(self) -> str:
        """
        Generates a human-typed recovery code (for master password recovery).

        Important property: without this code, the vault is unrecoverable
        (zero-knowledge).

        Returns: an uppercase hex code grouped like XXXX-XXXX-XXXX-XXXX
        """
        token = secrets.token_hex(16).upper()  # 32 hex chars = 128 bits
        groups = [token[i:i + 4] for i in range(0, len(token), 4)]
        return "-".join(groups)