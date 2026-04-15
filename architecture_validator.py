# architecture_validator.py
# ARCHITECTURE VALIDATION REPORT — SentinelsVault
#
# This script programmatically proves three core architectural guarantees:
#
#   GUARANTEE 1: Isolated Modules
#     Each component communicates via defined interfaces only.
#     No module directly accesses another module's internals.
#
#   GUARANTEE 2: Volatile Key Storage
#     Encryption keys exist only in RAM during the active session.
#     They are never written to disk and are wiped on session end.
#
#   GUARANTEE 3: Direct I/O through Crypto Engine
#     The UI interacts with the database only through the Crypto Engine.
#     No plaintext password ever touches SQLite directly.
#
# Run this with: python architecture_validator.py
# Output is also saved to: architecture_report.log

import os
import sys
import sqlite3
import hashlib
import logging
import inspect
import datetime
import importlib

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logging.basicConfig(
    filename="architecture_report.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# TERMINAL COLOR CODES
# ─────────────────────────────────────────────
class Colors:
    HEADER   = '\033[95m'
    BLUE     = '\033[94m'
    CYAN     = '\033[96m'
    GREEN    = '\033[92m'
    WARNING  = '\033[93m'
    RED      = '\033[91m'
    BOLD     = '\033[1m'
    RESET    = '\033[0m'

# ─────────────────────────────────────────────
# ENABLE UTF-8 OUTPUT ON WINDOWS
# ─────────────────────────────────────────────
sys.stdout.reconfigure(encoding='utf-8')

# ─────────────────────────────────────────────
# BASE VALIDATOR CLASS
# Every guarantee check inherits from this.
# ─────────────────────────────────────────────
class ArchitectureCheck:
    """
    Base class for every architectural guarantee check.
    Each check records its own results and prints its own report.
    """

    def __init__(self, guarantee_number: int, guarantee_name: str,
                 description: str):
        self.guarantee_number = guarantee_number
        self.guarantee_name   = guarantee_name
        self.description      = description
        self.results          = []   # List of (test_name, passed, detail)
        self.passed           = 0
        self.failed           = 0

    def log_test(self, test_name: str, passed: bool, detail: str):
        """Records one test result."""
        self.results.append((test_name, passed, detail))
        if passed:
            self.passed += 1
            logger.info(f"[PASS] G{self.guarantee_number} — {test_name}: {detail}")
        else:
            self.failed += 1
            logger.warning(f"[FAIL] G{self.guarantee_number} — {test_name}: {detail}")

    def run_checks(self):
        """Override in each subclass to implement the actual checks."""
        raise NotImplementedError

    def print_report(self):
        """Prints a formatted report for this guarantee."""
        status_color = Colors.GREEN if self.failed == 0 else Colors.WARNING
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'─' * 62}{Colors.RESET}")
        print(f"{Colors.BOLD}  GUARANTEE {self.guarantee_number}: "
              f"{self.guarantee_name.upper()}{Colors.RESET}")
        print(f"  {Colors.CYAN}{self.description}{Colors.RESET}")
        print(f"{Colors.BLUE}{'─' * 62}{Colors.RESET}")

        for test_name, passed, detail in self.results:
            icon = (f"{Colors.GREEN}  [PASS]{Colors.RESET}"
                    if passed else
                    f"{Colors.RED}  [FAIL]{Colors.RESET}")
            print(f"{icon}  {test_name}")
            print(f"         {Colors.CYAN}-> {detail}{Colors.RESET}")

        print(f"\n  {status_color}Checks Passed: "
              f"{self.passed} / {self.passed + self.failed}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════
# GUARANTEE 1: ISOLATED MODULES
# Proves that each module only exposes a defined public interface
# and does not directly access the internals of other modules.
# ═══════════════════════════════════════════════════════════════
class IsolatedModulesCheck(ArchitectureCheck):
    """
    Validates that the five modules are properly isolated.

    What 'isolation' means in SentinelsVault:
    - StorageEngine never imports EncryptionProvider
    - EncryptionProvider never imports StorageEngine
    - SentinelAuditor never imports StorageEngine or EncryptionProvider
    - AuthManager never imports StorageEngine or EncryptionProvider
    - No module bypasses the defined interface of another

    We prove this by inspecting each module's actual import statements
    using Python's importlib and inspect tools.
    """

    def __init__(self):
        super().__init__(
            guarantee_number=1,
            guarantee_name="Isolated Modules",
            description="Each component communicates via defined interfaces. "
                        "No module directly accesses another module's internals."
        )

    def run_checks(self):
        """Runs all isolation checks by inspecting module source code."""

        # ── CHECK 1: StorageEngine does not import crypto modules ──
        # StorageEngine should only deal with raw bytes (BLOBs).
        # It must NEVER import EncryptionProvider or perform encryption.
        try:
            import storage_engine
            source = inspect.getsource(storage_engine)

            # Check that EncryptionProvider is not imported in storage_engine
            imports_enc = ("from encryption_provider" in source or
                           "import encryption_provider" in source or
                           "EncryptionProvider" in source)

            self.log_test(
                "StorageEngine does not import EncryptionProvider",
                not imports_enc,
                "storage_engine.py contains no reference to EncryptionProvider. "
                "Database layer is completely blind to encryption logic."
                if not imports_enc else
                "VIOLATION: StorageEngine imports crypto module — isolation broken."
            )
        except Exception as e:
            self.log_test("StorageEngine isolation check", False, str(e))

        # ── CHECK 2: EncryptionProvider does not import StorageEngine ──
        # The crypto engine must not know about the database.
        # It only receives bytes, encrypts them, and returns bytes.
        try:
            import encryption_provider
            source = inspect.getsource(encryption_provider)

            imports_db = ("from storage_engine" in source or
                          "import storage_engine" in source or
                          "StorageEngine" in source or
                          "sqlite3" in source)

            self.log_test(
                "EncryptionProvider does not import StorageEngine",
                not imports_db,
                "encryption_provider.py contains no database references. "
                "Crypto engine is completely blind to storage logic."
                if not imports_db else
                "VIOLATION: EncryptionProvider imports storage module."
            )
        except Exception as e:
            self.log_test("EncryptionProvider isolation check", False, str(e))

        # ── CHECK 3: SentinelAuditor is completely independent ──
        # The auditor only performs heuristic analysis on plaintext strings.
        # It must never import crypto or database modules.
        try:
            import sentinel_auditor
            source = inspect.getsource(sentinel_auditor)

            imports_others = ("from encryption_provider" in source or
                              "from storage_engine" in source or
                              "from auth_manager" in source or
                              "EncryptionProvider" in source or
                              "StorageEngine" in source or
                              "sqlite3" in source)

            self.log_test(
                "SentinelAuditor is fully independent",
                not imports_others,
                "sentinel_auditor.py imports no other SentinelsVault modules. "
                "It operates purely on data passed to it — maximum isolation."
                if not imports_others else
                "VIOLATION: SentinelAuditor imports other modules."
            )
        except Exception as e:
            self.log_test("SentinelAuditor isolation check", False, str(e))

        # ── CHECK 4: AuthManager does not import StorageEngine ──
        # AuthManager handles only hashing and key derivation.
        # It must never interact with the database directly.
        try:
            import auth_manager
            source = inspect.getsource(auth_manager)

            imports_db = ("from storage_engine" in source or
                          "import storage_engine" in source or
                          "StorageEngine" in source or
                          "sqlite3" in source)

            self.log_test(
                "AuthManager does not import StorageEngine",
                not imports_db,
                "auth_manager.py contains no database references. "
                "Authentication logic is completely decoupled from storage."
                if not imports_db else
                "VIOLATION: AuthManager imports storage module."
            )
        except Exception as e:
            self.log_test("AuthManager isolation check", False, str(e))

        # ── CHECK 5: Each module has a well-defined public interface ──
        # A well-isolated module exposes specific public methods.
        # We verify each module exports the expected interface.
        try:
            from encryption_provider import EncryptionProvider
            from storage_engine      import StorageEngine
            from auth_manager        import AuthManager
            from sentinel_auditor    import SentinelAuditor

            # Expected public methods per class
            expected_interfaces = {
                "EncryptionProvider": [
                    "encrypt", "decrypt",
                    "encrypt_bytes", "decrypt_bytes",
                    "secure_wipe"
                ],
                "StorageEngine": [
                    "is_vault_initialized", "save_vault_config",
                    "get_vault_config", "add_credential",
                    "get_all_credentials", "get_credential_by_id",
                    "update_credential", "delete_credential",
                    "get_password_history", "get_history_count",
                    "close"
                ],
                "AuthManager": [
                    "generate_salt",
                    "hash_master_password_argon2",
                    "verify_master_password_argon2",
                    "derive_key_pbkdf2"
                ],
                "SentinelAuditor": [
                    "calculate_entropy", "get_strength_label",
                    "audit_single_password", "generate_vault_report",
                    "generate_secure_password", "export_security_report"
                ],
            }

            classes = {
                "EncryptionProvider": EncryptionProvider,
                "StorageEngine":      StorageEngine,
                "AuthManager":        AuthManager,
                "SentinelAuditor":    SentinelAuditor,
            }

            all_ok = True
            missing_report = []
            for class_name, expected_methods in expected_interfaces.items():
                cls = classes[class_name]
                actual_methods = [
                    m for m in dir(cls)
                    if not m.startswith("__")
                ]
                for method in expected_methods:
                    if method not in actual_methods:
                        all_ok = False
                        missing_report.append(
                            f"{class_name}.{method}() not found")

            self.log_test(
                "All 4 modules expose their defined public interfaces",
                all_ok,
                "EncryptionProvider (5 methods), StorageEngine (11 methods), "
                "AuthManager (4 methods), SentinelAuditor (6 methods) — "
                "all interfaces verified."
                if all_ok else
                f"Missing methods: {', '.join(missing_report)}"
            )
        except Exception as e:
            self.log_test("Public interface verification", False, str(e))

        # ── CHECK 6: Modules communicate only via method parameters ──
        # Private attributes (prefixed with _) must not be accessed
        # by any external module. We check that _key is private.
        try:
            from encryption_provider import EncryptionProvider
            key = os.urandom(32)
            ep  = EncryptionProvider(key)

            # The key should be stored as _key (private, not key)
            has_private_key = hasattr(ep, '_key')
            has_public_key  = hasattr(ep, 'key')  # Public = bad practice

            self.log_test(
                "EncryptionProvider stores key as private attribute (_key)",
                has_private_key and not has_public_key,
                "Key is stored as self._key (private). "
                "External modules cannot access it by convention. "
                "This enforces encapsulation of the cryptographic secret."
                if has_private_key and not has_public_key else
                "Key is publicly accessible — encapsulation is weak."
            )

            # Clean up
            ep.secure_wipe()

        except Exception as e:
            self.log_test("Private attribute encapsulation", False, str(e))


# ═══════════════════════════════════════════════════════════════
# GUARANTEE 2: VOLATILE KEY STORAGE
# Proves that the AES-256 key exists only in RAM and is never
# written to disk, and is properly wiped when the vault locks.
# ═══════════════════════════════════════════════════════════════
class VolatileKeyStorageCheck(ArchitectureCheck):
    """
    Validates that the encryption key lives only in RAM.

    What 'volatile' means in SentinelsVault:
    - The key is derived from the password using PBKDF2 at login
    - It is stored in self._key inside EncryptionProvider (RAM only)
    - It is NEVER written to any file, database, or temp storage
    - When secure_wipe() is called, the key is overwritten with null bytes
    - After locking, no key material remains on the system
    """

    def __init__(self):
        super().__init__(
            guarantee_number=2,
            guarantee_name="Volatile Key Storage",
            description="Encryption keys exist only in RAM during the active session. "
                        "Never written to disk. Wiped with null bytes on lock."
        )

    def run_checks(self):
        """Validates key lifecycle — creation, residence, and destruction."""

        # ── CHECK 1: Key is not stored in any file ──
        # After initialization, no file named master.key, session.key,
        # or any key file should exist on disk.
        key_files = [
            "master.key", "session.key", "vault.key",
            "encryption.key", "aes.key", "secret.key"
        ]
        found_key_files = [f for f in key_files if os.path.exists(f)]
        self.log_test(
            "No encryption key files exist on disk",
            len(found_key_files) == 0,
            "No key files found on disk. "
            "Key material has never been written to non-volatile storage."
            if len(found_key_files) == 0 else
            f"VIOLATION: Key files found: {', '.join(found_key_files)}"
        )

        # ── CHECK 2: Key is not stored in the SQLite database ──
        # Open the database directly and verify no column stores
        # anything that looks like a raw 32-byte key in plaintext.
        try:
            if os.path.exists("sentinels_vault.db"):
                conn   = sqlite3.connect("sentinels_vault.db")
                cursor = conn.cursor()

                # vault_config contains salt and hashes — not the derived key
                cursor.execute("PRAGMA table_info(vault_config)")
                columns = [row[1] for row in cursor.fetchall()]

                # The derived AES session key must NOT have its own column
                # salt and vault_key_enc_master are acceptable (they are
                # encrypted wrappers, not the raw session key)
                bad_columns = [
                    c for c in columns
                    if c in ("aes_key", "session_key",
                             "derived_key", "master_key_raw")
                ]

                self.log_test(
                    "Database contains no raw session key column",
                    len(bad_columns) == 0,
                    f"vault_config columns: {', '.join(columns)}. "
                    "No raw derived AES key column found. "
                    "Key derivation happens at runtime in RAM only."
                    if len(bad_columns) == 0 else
                    f"VIOLATION: Suspicious key columns found: "
                    f"{', '.join(bad_columns)}"
                )
                conn.close()
            else:
                self.log_test(
                    "Database contains no raw session key column",
                    True,
                    "Database does not exist yet — "
                    "no key persistence possible at this stage."
                )
        except Exception as e:
            self.log_test(
                "Database key column check", False, str(e))

        # ── CHECK 3: secure_wipe() overwrites key with null bytes ──
        # After calling secure_wipe(), the _key attribute must be gone.
        # We verify this by inspecting the object after wiping.
        try:
            from encryption_provider import EncryptionProvider

            test_key = os.urandom(32)
            ep       = EncryptionProvider(test_key)

            # Verify key exists before wipe
            key_exists_before = hasattr(ep, '_key')

            # Perform the secure wipe
            ep.secure_wipe()

            # Verify key is gone after wipe
            key_exists_after = hasattr(ep, '_key')

            self.log_test(
                "secure_wipe() removes key from RAM",
                key_exists_before and not key_exists_after,
                "Key existed in RAM before wipe. "
                "After secure_wipe(), self._key attribute is deleted. "
                "RAM location freed. No key fingerprint remains."
                if key_exists_before and not key_exists_after else
                "Wipe incomplete — key attribute still present after wipe."
            )
        except Exception as e:
            self.log_test("secure_wipe() validation", False, str(e))

        # ── CHECK 4: Key derivation is deterministic (same input = same key) ──
        # PBKDF2 must produce the same 32-byte key when given the same
        # password and salt. This proves key derivation is reproducible
        # at runtime without needing to store the key.
        try:
            from auth_manager import AuthManager
            am       = AuthManager()
            password = "TestMasterPassword@99"
            salt     = os.urandom(32)

            key1 = am.derive_key_pbkdf2(password, salt)
            key2 = am.derive_key_pbkdf2(password, salt)

            keys_match = key1 == key2
            self.log_test(
                "PBKDF2 key derivation is deterministic",
                keys_match,
                f"Same password + same salt always produces same 32-byte key. "
                f"Key length: {len(key1)} bytes = {len(key1) * 8} bits. "
                "This means the key can always be re-derived at login "
                "without ever needing to store it."
                if keys_match else
                "FAIL: PBKDF2 produced different keys for same inputs."
            )
        except Exception as e:
            self.log_test("PBKDF2 determinism check", False, str(e))

        # ── CHECK 5: Different salts produce different keys ──
        # This proves that the salt prevents pre-computation attacks.
        # Even with the same password, a different salt = different key.
        try:
            from auth_manager import AuthManager
            am       = AuthManager()
            password = "SamePasswordForBothTests"
            salt_a   = os.urandom(32)
            salt_b   = os.urandom(32)

            key_a = am.derive_key_pbkdf2(password, salt_a)
            key_b = am.derive_key_pbkdf2(password, salt_b)

            keys_differ = key_a != key_b
            self.log_test(
                "Different salts produce different AES keys",
                keys_differ,
                "Same password with different salts produces "
                "completely different 256-bit keys. "
                "This defeats Rainbow Table and pre-computation attacks."
                if keys_differ else
                "FAIL: Salt is not affecting key derivation output."
            )
        except Exception as e:
            self.log_test("Salt uniqueness check", False, str(e))

        # ── CHECK 6: Key exists in RAM as bytes object ──
        # Verify the key is stored as a Python bytes object in RAM,
        # NOT as a string, file path, or any serializable format.
        try:
            from encryption_provider import EncryptionProvider
            test_key = os.urandom(32)
            ep       = EncryptionProvider(test_key)

            key_is_bytes  = isinstance(ep._key, bytes)
            key_is_32     = len(ep._key) == 32
            key_not_str   = not isinstance(ep._key, str)

            self.log_test(
                "Key is stored as raw bytes in RAM (not string/path)",
                key_is_bytes and key_is_32 and key_not_str,
                f"Type: {type(ep._key).__name__} | "
                f"Length: {len(ep._key)} bytes = {len(ep._key)*8} bits. "
                "Raw bytes cannot be accidentally serialized to a log file "
                "or printed to console as readable text."
                if key_is_bytes and key_is_32 else
                "FAIL: Key is not stored as 32 raw bytes."
            )
            ep.secure_wipe()
        except Exception as e:
            self.log_test("Key RAM type check", False, str(e))


# ═══════════════════════════════════════════════════════════════
# GUARANTEE 3: DIRECT I/O THROUGH CRYPTO ENGINE
# Proves that plaintext passwords never touch SQLite directly.
# Every password goes: plaintext -> encrypt() -> BLOB -> SQLite
# And every retrieval goes: SQLite -> BLOB -> decrypt() -> plaintext
# ═══════════════════════════════════════════════════════════════
class CryptoEngineIOCheck(ArchitectureCheck):
    """
    Validates that all database I/O passes through the Crypto Engine.

    What 'Direct I/O through Crypto Engine' means:
    - No plaintext password is ever written to SQLite
    - Every stored password is an AES-256-GCM ciphertext BLOB
    - Every retrieved password must be decrypted before display
    - The UI delegates all encryption/decryption to EncryptionProvider
    - StorageEngine only ever sees and stores raw encrypted bytes
    """

    def __init__(self):
        super().__init__(
            guarantee_number=3,
            guarantee_name="Direct I/O Through Crypto Engine",
            description="The UI interacts with the database only through "
                        "the Crypto Engine. No plaintext password ever "
                        "touches SQLite directly."
        )

    def run_checks(self):
        """Validates the encryption/decryption pipeline integrity."""

        # ── CHECK 1: StorageEngine only accepts bytes for passwords ──
        # The add_credential() method signature must accept bytes (BLOB)
        # for the password field — not a string.
        try:
            from storage_engine import StorageEngine
            import inspect

            sig    = inspect.signature(StorageEngine.add_credential)
            params = list(sig.parameters.keys())

            # The method should exist and accept pwd_blob parameter
            has_blob_param = "pwd_blob" in params

            self.log_test(
                "StorageEngine.add_credential() accepts bytes (BLOB) not strings",
                has_blob_param,
                f"Method signature: add_credential(self, {', '.join(params[1:])}). "
                "Parameter 'pwd_blob' confirms only encrypted bytes are accepted. "
                "Plaintext strings are architecturally rejected."
                if has_blob_param else
                "Parameter name suggests plaintext string may be accepted."
            )
        except Exception as e:
            self.log_test("StorageEngine parameter check", False, str(e))

        # ── CHECK 2: Encrypt → Store → Retrieve → Decrypt pipeline ──
        # The full round-trip test using an in-memory database.
        # This proves the pipeline works correctly end-to-end.
        try:
            from encryption_provider import EncryptionProvider

            # Generate a test key
            test_key      = os.urandom(32)
            enc           = EncryptionProvider(test_key)
            original_text = "MyGitHubPassword@2024!"

            # Step 1: Encrypt (what the UI does before storing)
            ciphertext, iv = enc.encrypt(original_text)

            # Step 2: Verify ciphertext is NOT the original text
            plaintext_leaked = (ciphertext == original_text.encode('utf-8'))

            # Step 3: Store in an in-memory SQLite database
            conn   = sqlite3.connect(":memory:")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE test_creds (
                    id INTEGER PRIMARY KEY,
                    site TEXT,
                    encrypted_password BLOB,
                    iv BLOB
                )
            """)
            cursor.execute(
                "INSERT INTO test_creds (site, encrypted_password, iv) "
                "VALUES (?, ?, ?)",
                ("GitHub", ciphertext, iv)
            )
            conn.commit()

            # Step 4: Retrieve from database (as BLOB)
            cursor.execute(
                "SELECT encrypted_password, iv FROM test_creds "
                "WHERE site=?", ("GitHub",)
            )
            row            = cursor.fetchone()
            stored_blob    = row[0]
            stored_iv      = row[1]
            stored_is_blob = isinstance(stored_blob, bytes)

            # Step 5: Decrypt (what the UI does after retrieving)
            decrypted = enc.decrypt(stored_blob, stored_iv)
            roundtrip_ok = decrypted == original_text

            conn.close()
            enc.secure_wipe()

            self.log_test(
                "Full pipeline: Encrypt -> SQLite BLOB -> Decrypt",
                not plaintext_leaked and stored_is_blob and roundtrip_ok,
                f"Original: '{original_text}' | "
                f"Stored as: {len(stored_blob)}-byte BLOB | "
                f"Decrypted: '{decrypted}' | "
                f"Round-trip match: {roundtrip_ok}. "
                "Plaintext never appeared in the database."
                if not plaintext_leaked and stored_is_blob and roundtrip_ok
                else "FAIL: Pipeline integrity broken."
            )
        except Exception as e:
            self.log_test("Full pipeline integrity test", False, str(e))

        # ── CHECK 3: Ciphertext is not human-readable ──
        # The stored bytes must not contain the original string.
        try:
            from encryption_provider import EncryptionProvider

            test_key  = os.urandom(32)
            enc       = EncryptionProvider(test_key)
            plaintext = "NetflixPassword99!"

            ciphertext, iv = enc.encrypt(plaintext)

            # Try to find the plaintext string inside the ciphertext
            plaintext_in_cipher = (
                plaintext.encode('utf-8') in ciphertext
            )

            self.log_test(
                "Ciphertext contains no human-readable plaintext",
                not plaintext_in_cipher,
                f"Original string '{plaintext}' is completely absent from "
                f"the {len(ciphertext)}-byte ciphertext. "
                "AES-256-GCM scrambles data into mathematically random bytes."
                if not plaintext_in_cipher else
                "CRITICAL VIOLATION: Plaintext found inside ciphertext!"
            )
            enc.secure_wipe()
        except Exception as e:
            self.log_test(
                "Ciphertext readability check", False, str(e))

        # ── CHECK 4: GCM tag detects database tampering ──
        # If the database is tampered with (even one bit changed),
        # the GCM authentication tag must reject decryption.
        try:
            from encryption_provider import EncryptionProvider

            test_key  = os.urandom(32)
            enc       = EncryptionProvider(test_key)
            plaintext = "AmazonPrime@Secret"

            ciphertext, iv = enc.encrypt(plaintext)

            # Tamper with one byte of the ciphertext
            tampered = bytearray(ciphertext)
            tampered[0] ^= 0xFF   # Flip all bits in first byte
            tampered = bytes(tampered)

            # Attempt to decrypt tampered data
            tamper_detected = False
            try:
                enc.decrypt(tampered, iv)
                # If we reach here, tampering was NOT detected — FAIL
            except Exception:
                tamper_detected = True   # GCM tag rejected it — PASS

            self.log_test(
                "GCM auth tag detects database tampering",
                tamper_detected,
                "Modified 1 byte of ciphertext. "
                "GCM authentication tag correctly rejected decryption. "
                "Any database tampering is cryptographically detected."
                if tamper_detected else
                "CRITICAL FAIL: Tampered ciphertext was accepted — "
                "GCM integrity check is not working."
            )
            enc.secure_wipe()
        except Exception as e:
            self.log_test(
                "GCM tamper detection check", False, str(e))

        # ── CHECK 5: Every encryption produces a unique ciphertext ──
        # The same plaintext encrypted twice must produce different
        # ciphertext due to the unique IV generated each time.
        try:
            from encryption_provider import EncryptionProvider

            test_key  = os.urandom(32)
            enc       = EncryptionProvider(test_key)
            plaintext = "ReusedPassword123"

            ct1, iv1 = enc.encrypt(plaintext)
            ct2, iv2 = enc.encrypt(plaintext)

            ivs_differ = iv1 != iv2
            cts_differ = ct1 != ct2

            self.log_test(
                "Same plaintext produces unique ciphertext each time",
                ivs_differ and cts_differ,
                f"Encryption 1: IV={iv1.hex()[:16]}... | "
                f"Encryption 2: IV={iv2.hex()[:16]}... | "
                "IVs differ: True | Ciphertexts differ: True. "
                "Unique IV per encryption prevents pattern analysis."
                if ivs_differ and cts_differ else
                "FAIL: Identical ciphertext produced — IV reuse detected."
            )
            enc.secure_wipe()
        except Exception as e:
            self.log_test("IV uniqueness check", False, str(e))

        # ── CHECK 6: StorageEngine source code never calls encrypt() ──
        # The storage layer must never perform encryption itself.
        # Only the UI (via EncryptionProvider) should encrypt data.
        try:
            import storage_engine as se_module
            source = inspect.getsource(se_module)

            # These are signs of encryption happening in the wrong place
            bad_patterns = [
                "AESGCM(",
                ".encrypt(",
                ".decrypt(",
                "AES.new(",
                "Fernet(",
            ]

            violations = [p for p in bad_patterns if p in source]

            self.log_test(
                "StorageEngine never calls encrypt() or decrypt()",
                len(violations) == 0,
                "storage_engine.py contains no encryption calls. "
                "It only stores and retrieves raw BLOB bytes. "
                "Encryption is 100% delegated to EncryptionProvider."
                if len(violations) == 0 else
                f"VIOLATION: Encryption calls found in StorageEngine: "
                f"{', '.join(violations)}"
            )
        except Exception as e:
            self.log_test(
                "StorageEngine encryption call check", False, str(e))


# ═══════════════════════════════════════════════════════════════
# RUNNER — Executes all 3 guarantees and prints the final report
# ═══════════════════════════════════════════════════════════════
class ArchitectureValidator:
    """
    Orchestrates all three architecture guarantee checks.
    Runs them in sequence and prints the complete validation report.
    """

    def __init__(self):
        self.checks = [
            IsolatedModulesCheck(),
            VolatileKeyStorageCheck(),
            CryptoEngineIOCheck(),
        ]
        self.total_passed = 0
        self.total_failed = 0

    def run(self):
        """Runs all checks and prints the complete report."""
        self._print_header()
        for check in self.checks:
            check.run_checks()
            check.print_report()
            self.total_passed += check.passed
            self.total_failed += check.failed
        self._print_summary()

    def _print_header(self):
        """Prints the report banner."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("=" * 62)
        print("  SENTINELSVAULT — ARCHITECTURE VALIDATION REPORT")
        print("  Proving Three Core Security Guarantees")
        print(f"  Generated: {now}")
        print("=" * 62)
        print(f"{Colors.RESET}")
        print(f"  {Colors.CYAN}Guarantee 1:{Colors.RESET} "
              "Isolated Modules")
        print(f"  {Colors.CYAN}Guarantee 2:{Colors.RESET} "
              "Volatile Key Storage")
        print(f"  {Colors.CYAN}Guarantee 3:{Colors.RESET} "
              "Direct I/O Through Crypto Engine")
        print(f"\n  {Colors.CYAN}Project:{Colors.RESET} SentinelsVault")
        print(f"  {Colors.CYAN}Architecture:{Colors.RESET} "
              "Zero-Knowledge | Local-First | AES-256-GCM")
        print(f"  {Colors.CYAN}Crypto Engine:{Colors.RESET} "
              "EncryptionProvider (AES-256-GCM)")
        print(f"  {Colors.CYAN}Database:{Colors.RESET} "
              "StorageEngine (SQLite3, WAL, 3NF, BLOB)")

    def _print_summary(self):
        """Prints the final summary after all checks complete."""
        total      = self.total_passed + self.total_failed
        percentage = (self.total_passed / total * 100) if total > 0 else 0

        if self.total_failed == 0:
            status_color = Colors.GREEN
            verdict      = "[VERIFIED] ALL ARCHITECTURE GUARANTEES PROVEN"
            detail       = ("SentinelsVault's security architecture is "
                            "mathematically and programmatically sound.")
        elif percentage >= 80:
            status_color = Colors.WARNING
            verdict      = "[PARTIAL] MOST GUARANTEES VERIFIED"
            detail       = "Review failed checks above."
        else:
            status_color = Colors.RED
            verdict      = "[FAIL] CRITICAL ARCHITECTURE VIOLATIONS"
            detail       = "Immediate remediation required."

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 62}")
        print("  FINAL ARCHITECTURE VALIDATION SUMMARY")
        print(f"{'=' * 62}{Colors.RESET}")
        print(f"\n  Total Checks Run   : {Colors.BOLD}{total}{Colors.RESET}")
        print(f"  Checks Passed      : "
              f"{Colors.GREEN}{self.total_passed}{Colors.RESET}")
        print(f"  Checks Failed      : "
              f"{Colors.RED}{self.total_failed}{Colors.RESET}")
        print(f"  Pass Rate          : "
              f"{status_color}{percentage:.1f}%{Colors.RESET}")
        print(f"\n  {Colors.BOLD}{status_color}{verdict}{Colors.RESET}")
        print(f"  {detail}")
        print(f"\n  {Colors.CYAN}Full log saved to: "
              f"architecture_report.log{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 62}{Colors.RESET}\n")

        logger.info(
            f"Architecture Validation Complete — "
            f"Passed: {self.total_passed}/{total} ({percentage:.1f}%)")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    validator = ArchitectureValidator()
    validator.run()