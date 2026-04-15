# class_diagram.py
# UML Class Diagram for SentinelsVault
# 
# This file generates a professional ASCII UML Class Diagram showing:
#   - All 5 main classes with their attributes and methods
#   - Relationships (composition, dependency, association)
#   - Multiplicity indicators
#   - Data types and visibility modifiers
#
# Run with: python class_diagram.py

import sys
import io

# Configure console for UTF-8 on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def print_header():
    """Print the diagram header."""
    print("=" * 80)
    print("                    SENTINELSVAULT - UML CLASS DIAGRAM")
    print("                    Enterprise-Grade Cryptographic Password Manager")
    print("=" * 80)
    print()
    print("Legend:")
    print("  ┌─────────────────────────────────────────────────────────────────────────┐")
    print("  │  + : public      - : private      # : protected      ~ : package        │")
    print("  │  <<interface>> : interface    <<abstract>> : abstract class             │")
    print("  │  ◇─── : composition (has-a)    ╌╌╌> : dependency (uses-a)               │")
    print("  │  └─── : association (knows-a)   <│─── : inheritance (is-a)              │")
    print("  └─────────────────────────────────────────────────────────────────────────┘")
    print()
    print()


def print_class_auth_manager():
    """Print AuthManager class (Module 1: Authentication & Key Derivation)."""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│                    <<class>> AuthManager                         │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  - ph: PasswordHasher                                            │")
    print("│  - salt_size: int = 32                                           │")
    print("│  - key_length: int = 32                                          │")
    print("│  - pbkdf2_iterations: int = 600000                               │")
    print("│  - argon2_time_cost: int = 2                                     │")
    print("│  - argon2_memory_cost: int = 65536                               │")
    print("│  - argon2_parallelism: int = 2                                   │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  + __init__()                                                    │")
    print("│  + generate_salt() : bytes                                       │")
    print("│  + hash_master_password_argon2(password: str) : str              │")
    print("│  + verify_master_password_argon2(stored_hash: str,               │")
    print("│                        entered_password: str) : bool             │")
    print("│  + derive_key_pbkdf2(password: str, salt: bytes) : bytes         │")
    print("│  + generate_recovery_code() : str                                │")
    print("│  - _secure_wipe(sensitive_data) : None                           │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()


def print_class_encryption_provider():
    """Print EncryptionProvider class (Module 2: Cryptographic Engine)."""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│                 <<class>> EncryptionProvider                     │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  - _key: bytes                                                   │")
    print("│  - aesgcm: AESGCM                                                │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  + __init__(key: bytes)                                          │")
    print("│  + encrypt(plaintext: str) : tuple[bytes, bytes]                 │")
    print("│  + decrypt(ciphertext: bytes, nonce: bytes) : str                │")
    print("│  + encrypt_bytes(plaintext: bytes) : tuple[bytes, bytes]         │")
    print("│  + decrypt_bytes(ciphertext: bytes, nonce: bytes) : bytes        │")
    print("│  + secure_wipe() : None                                          │")
    print("│  - _generate_nonce() : bytes                                     │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()


def print_class_storage_engine():
    """Print StorageEngine class (Module 3: Data Management)."""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│                   <<class>> StorageEngine                        │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  - conn: sqlite3.Connection                                      │")
    print("│  - cursor: sqlite3.Cursor                                        │")
    print("│  - DATABASE_FILE: str = 'sentinels_vault.db'                     │")
    print("│  - MAX_HISTORY_PER_CREDENTIAL: int = 10                          │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  + __init__()                                                    │")
    print("│  + is_vault_initialized() : bool                                 │")
    print("│  + save_vault_config(salt: bytes, master_hash: str, ...) : None  │")
    print("│  + get_vault_config() : tuple                                     │")
    print("│  + add_credential(site, user, pwd_blob, iv, cat, notes) : None   │")
    print("│  + get_all_credentials() : list                                  │")
    print("│  + get_credential_by_id(cred_id: int) : tuple                    │")
    print("│  + update_credential(cred_id, site, user, ...) : None            │")
    print("│  + delete_credential(cred_id: int) : None                        │")
    print("│  + search_credentials(search_text: str) : list                   │")
    print("│  + get_password_history(credential_id: int) : list               │")
    print("│  + get_history_count(credential_id: int) : int                   │")
    print("│  + close() : None                                                │")
    print("│  - _initialize_tables() : None                                   │")
    print("│  - _save_to_history(credential_id, old_enc, old_iv) : None       │")
    print("│  - _enforce_history_limit(credential_id) : None                  │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()


def print_class_sentinel_auditor():
    """Print SentinelAuditor class (Module 4: Security Auditor)."""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│                  <<class>> SentinelAuditor                       │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  - _instance: SentinelAuditor = None  (Singleton)                │")
    print("│  - _initialized: bool = False                                    │")
    print("│  - _common_passwords: Set[str]                                   │")
    print("│  - _character_pool_sizes: Dict[str, int]                         │")
    print("│  - _entropy_thresholds: Dict[PasswordStrength, float]            │")
    print("│  - _audit_cache: Dict[str, PasswordAuditResult]                  │")
    print("│  - _cache_max_size: int = 1000                                   │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  + __new__(cls) : SentinelAuditor  (Singleton)                   │")
    print("│  + __init__()                                                    │")
    print("│  + calculate_entropy(password: str) : float                      │")
    print("│  + get_strength_label(entropy: float) : tuple[str, str]          │")
    print("│  + audit_single_password(password: str) : dict                   │")
    print("│  + generate_vault_report(decrypted_credentials: list) : dict     │")
    print("│  + generate_comprehensive_report(credentials: list) : object     │")
    print("│  + get_strength_guide() : dict                                   │")
    print("│  + generate_secure_password(length: int) : str                   │")
    print("│  + generate_custom_password(length, use_upper, ...) : str        │")
    print("│  + export_security_report(list, score, filepath) : tuple         │")
    print("│  - _calculate_entropy(password) : float                          │")
    print("│  - _get_strength_from_entropy(entropy) : PasswordStrength        │")
    print("│  - _identify_issues(password, entropy, is_common) : list         │")
    print("│  - _calculate_vault_score(counter, common, reused) : int         │")
    print("│  - _analyze_by_category(credentials) : dict                      │")
    print("│  - _generate_recommendations(report, category) : list            │")
    print("│  - _cache_result(password, result) : None                        │")
    print("│  - _estimate_crack_time(entropy) : str                           │")
    print("│  - _get_risk_level(entropy, is_common) : str                     │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()


def print_class_app_ui():
    """Print SentinelsVaultApp class (Module 5: User Interface)."""
    print("┌─────────────────────────────────────────────────────────────────┐")
    print("│              <<class>> SentinelsVaultApp (CTk)                   │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  - auth_manager: AuthManager                                     │")
    print("│  - storage_engine: StorageEngine                                 │")
    print("│  - sentinel_auditor: SentinelAuditor                             │")
    print("│  - master_key: bytes                                             │")
    print("│  - encryption_provider: EncryptionProvider                       │")
    print("│  - session_timeout_seconds: int = 300                            │")
    print("│  - _auto_lock_enabled: bool                                      │")
    print("│  - _last_activity_ts: float                                      │")
    print("│  - _pending_totp: pyotp.TOTP                                     │")
    print("│  - sidebar: CTkFrame                                             │")
    print("│  - content: CTkFrame                                             │")
    print("│  ─────────────────────────────────────────────────────────────── │")
    print("│  + __init__()                                                    │")
    print("│  + clear_screen() : None                                         │")
    print("│  + clear_content() : None                                        │")
    print("│  + show_setup_screen() : None                                    │")
    print("│  + show_login_screen() : None                                    │")
    print("│  + show_dashboard() : None                                       │")
    print("│  + show_vault_view() : None                                      │")
    print("│  + show_add_view() : None                                        │")
    print("│  + show_audit_view() : None                                      │")
    print("│  + show_export_view() : None                                     │")
    print("│  + show_strength_guide() : None                                  │")
    print("│  + show_encryption_flow() : None                                 │")
    print("│  + show_attack_calculator() : None                               │")
    print("│  + show_comparison_table() : None                                │")
    print("│  + show_key_derivation_demo() : None                             │")
    print("│  + show_security_flowchart() : None                              │")
    print("│  + lock_vault() : None                                           │")
    print("│  + view_secret(cred_id) : None                                   │")
    print("│  + view_password_history(cred_id, site_name) : None              │")
    print("│  + delete_secret(cred_id, site_name) : None                      │")
    print("│  + arm_auto_lock() : None                                        │")
    print("│  - _check_idle() : None                                          │")
    print("│  - _note_activity(event) : None                                  │")
    print("└─────────────────────────────────────────────────────────────────┘")
    print()


def print_relationships():
    """Print the relationships between classes (UML arrows)."""
    print()
    print("=" * 80)
    print("                        CLASS RELATIONSHIPS")
    print("=" * 80)
    print()
    
    # Relationship diagram
    print("""
    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                              RELATIONSHIP DIAGRAM                                 │
    ├─────────────────────────────────────────────────────────────────────────────────┤
    │                                                                                  │
    │                              ┌─────────────────┐                                 │
    │                              │  main.py        │                                 │
    │                              │  (Entry Point)  │                                 │
    │                              └────────┬────────┘                                 │
    │                                       │                                          │
    │                                       │ creates and runs                         │
    │                                       ▼                                          │
    │   ┌─────────────────────────────────────────────────────────────────────────┐   │
    │   │                         SentinelsVaultApp                                │   │
    │   │                           (Main UI Class)                                │   │
    │   └─────────────────────────────────────────────────────────────────────────┘   │
    │                                       │                                          │
    │                    ┌──────────────────┼──────────────────┐                      │
    │                    │                  │                  │                      │
    │                    ▼                  ▼                  ▼                      │
    │         ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐        │
    │         │   AuthManager    │  │  StorageEngine   │  │  SentinelAuditor │        │
    │         │   (Module 1)     │  │   (Module 3)     │  │   (Module 4)     │        │
    │         └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘        │
    │                  │                     │                     │                  │
    │                  │ creates             │ uses                │ uses             │
    │                  ▼                     │                     │                  │
    │         ┌──────────────────┐           │                     │                  │
    │         │ EncryptionProvider│◄─────────┘                     │                  │
    │         │   (Module 2)      │                               │                  │
    │         └──────────────────┘                               │                  │
    │                                                             │                  │
    └─────────────────────────────────────────────────────────────────────────────────┘
    """)
    
    print()
    print("LEGEND FOR RELATIONSHIPS:")
    print("  ╌╌╌╌╌╌╌╌╌╌>  Dependency (uses-a) - temporary/transient relationship")
    print("  ───────────  Association (knows-a) - permanent reference")
    print("  ◇──────────  Composition (has-a) - owns, lifecycle dependent")
    print("  <│─────────  Inheritance (is-a) - subclass relationship")
    print()
    
    print("DETAILED RELATIONSHIPS:")
    print("  ┌─────────────────────────────────────────────────────────────────────┐")
    print("  │ 1. SentinelsVaultApp ◇───> AuthManager                               │")
    print("  │    (Composition: App owns AuthManager - created together)            │")
    print("  │                                                                      │")
    print("  │ 2. SentinelsVaultApp ◇───> StorageEngine                             │")
    print("  │    (Composition: App owns StorageEngine - database connection)       │")
    print("  │                                                                      │")
    print("  │ 3. SentinelsVaultApp ◇───> SentinelAuditor (Singleton)               │")
    print("  │    (Association: App uses shared auditor instance)                   │")
    print("  │                                                                      │")
    print("  │ 4. AuthManager ╌╌╌> EncryptionProvider                               │")
    print("  │    (Dependency: AuthManager creates EncryptionProvider temporarily)  │")
    print("  │                                                                      │")
    print("  │ 5. SentinelsVaultApp ◇───> EncryptionProvider                        │")
    print("  │    (Composition: App owns EncryptionProvider while vault unlocked)   │")
    print("  │                                                                      │")
    print("  │ 6. StorageEngine ╌╌╌> sqlite3.Connection                             │")
    print("  │    (Dependency: Uses external library)                               │")
    print("  │                                                                      │")
    print("  │ 7. EncryptionProvider ╌╌╌> cryptography.AESGCM                       │")
    print("  │    (Dependency: Uses external cryptography library)                  │")
    print("  │                                                                      │")
    print("  │ 8. AuthManager ╌╌╌> argon2.PasswordHasher                            │")
    print("  │    (Dependency: Uses external Argon2 library)                        │")
    print("  └─────────────────────────────────────────────────────────────────────┘")
    print()


def print_database_schema():
    """Print the database schema as a visual representation."""
    print()
    print("=" * 80)
    print("                     DATABASE SCHEMA (3rd Normal Form)")
    print("=" * 80)
    print()
    
    print("""
    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                              TABLE 1: vault_config                               │
    ├─────────────────────────────────────────────────────────────────────────────────┤
    │  PK  id              INTEGER      PRIMARY KEY                                   │
    │      salt            BLOB         NOT NULL                                      │
    │      master_hash     TEXT         NOT NULL                                      │
    │      mfa_secret      TEXT                                                       │
    │      recovery_salt   BLOB                                                       │
    │      vault_key_enc_master     BLOB                                              │
    │      vault_key_nonce_master   BLOB                                              │
    │      vault_key_enc_recovery   BLOB                                              │
    │      vault_key_nonce_recovery BLOB                                              │
    │      mfa_enabled     INTEGER                                                    │
    │      mfa_secret_enc  BLOB                                                       │
    │      mfa_secret_nonce BLOB                                                      │
    │      created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP                     │
    └─────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                              TABLE 2: credentials                                │
    ├─────────────────────────────────────────────────────────────────────────────────┤
    │  PK  id                  INTEGER      PRIMARY KEY AUTOINCREMENT                 │
    │      site_name           TEXT         NOT NULL                                  │
    │      username            TEXT         NOT NULL                                  │
    │      encrypted_password  BLOB         NOT NULL                                  │
    │      iv                  BLOB         NOT NULL                                  │
    │      category            TEXT         DEFAULT 'General'                         │
    │      notes               TEXT                                                   │
    │      created_at          TIMESTAMP    DEFAULT CURRENT_TIMESTAMP                 │
    │      last_updated        TIMESTAMP    DEFAULT CURRENT_TIMESTAMP                 │
    └─────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                              TABLE 3: password_history                          │
    ├─────────────────────────────────────────────────────────────────────────────────┤
    │  PK  id                      INTEGER      PRIMARY KEY AUTOINCREMENT             │
    │  FK  credential_id           INTEGER      NOT NULL REFERENCES credentials(id)   │
    │      old_encrypted_password  BLOB         NOT NULL                              │
    │      old_iv                  BLOB         NOT NULL                              │
    │      changed_at              TIMESTAMP    DEFAULT CURRENT_TIMESTAMP             │
    │      change_number           INTEGER      NOT NULL DEFAULT 1                    │
    │                                                                                  │
    │  CONSTRAINT: ON DELETE CASCADE (history deleted when credential deleted)        │
    └─────────────────────────────────────────────────────────────────────────────────┘
    """)
    
    print()
    print("NORMALIZATION VERIFICATION (3NF):")
    print("  ✓ 1NF: Atomic values, no repeating groups")
    print("  ✓ 2NF: No partial dependencies (all columns depend on full primary key)")
    print("  ✓ 3NF: No transitive dependencies (no column depends on another non-key)")
    print()


def print_sequence_flow():
    """Print a sequence diagram for login flow."""
    print()
    print("=" * 80)
    print("                     SEQUENCE DIAGRAM: Login Flow")
    print("=" * 80)
    print()
    
    print("""
    User          SentinelsVaultApp    AuthManager      StorageEngine    EncryptionProvider
     |                   |                  |                  |                   |
     |  Enter Password   |                  |                  |                   |
     |─────────────────>|                  |                  |                   |
     |                   |                  |                  |                   |
     |                   |  verify_password(pwd)              |                   |
     |                   |─────────────────>|                  |                   |
     |                   |                  |                  |                   |
     |                   |                  | get_vault_config()|                   |
     |                   |                  |─────────────────>|                   |
     |                   |                  |                  |                   |
     |                   |                  | return(salt,hash) |                   |
     |                   |                  |<─────────────────|                   |
     |                   |                  |                  |                   |
     |                   |                  | Argon2id verify   |                   |
     |                   |                  |──────────────┐    |                   |
     |                   |                  |              │    |                   |
     |                   |                  |<─────────────┘    |                   |
     |                   |                  |                  |                   |
     |                   |  return(True)    |                  |                   |
     |                   |<─────────────────|                  |                   |
     |                   |                  |                  |                   |
     |                   |  derive_key_pbkdf2(pwd, salt)       |                   |
     |                   |─────────────────>|                  |                   |
     |                   |                  |                  |                   |
     |                   |  return(key)     |                  |                   |
     |                   |<─────────────────|                  |                   |
     |                   |                  |                  |                   |
     |                   |  create EncryptionProvider(key)     |                   |
     |                   |─────────────────────────────────────────────────────>|
     |                   |                  |                  |                   |
     |                   |  return(provider)|                  |                   |
     |                   |<─────────────────────────────────────────────────────|
     |                   |                  |                  |                   |
     |                   |  show_dashboard()|                  |                   |
     |                   |──────────────┐   |                  |                   |
     |                   |              │   |                  |                   |
     |                   │<─────────────┘   |                  |                   |
     |                   |                  |                  |                   |
     |  Dashboard View   |                  |                  |                   |
     |<─────────────────|                  |                  |                   |
     |                   |                  |                  |                   |
    """)
    print()


def print_state_machine():
    """Print the vault state machine diagram."""
    print()
    print("=" * 80)
    print("                     STATE MACHINE: Vault Lifecycle")
    print("=" * 80)
    print()
    
    print("""
    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                              VAULT STATE MACHINE                                 │
    ├─────────────────────────────────────────────────────────────────────────────────┤
    │                                                                                  │
    │                              ┌─────────────────┐                                 │
    │                              │   NOT SETUP     │                                 │
    │                              │ (First Launch)  │                                 │
    │                              └────────┬────────┘                                 │
    │                                       │                                          │
    │                                       │ setup_complete()                         │
    │                                       ▼                                          │
    │   ┌─────────────────────────────────────────────────────────────────────────┐   │
    │   │                                                                          │   │
    │   │   ┌─────────────────┐     unlock()     ┌─────────────────┐              │   │
    │   │   │     LOCKED      │ ───────────────> │    UNLOCKED     │              │   │
    │   │   │  (Login Screen) │                  │  (Dashboard)    │              │   │
    │   │   └────────┬────────┘                  └────────┬────────┘              │   │
    │   │            │                                    │                        │   │
    │   │            │                                    │ auto_lock() /          │   │
    │   │            │                                    │ lock_vault()           │   │
    │   │            │                                    ▼                        │   │
    │   │            │                              ┌─────────────────┐            │   │
    │   │            │                              │   LOCKING      │            │   │
    │   │            │                              │  (Wiping RAM)  │            │   │
    │   │            │                              └────────┬────────┘            │   │
    │   │            │                                       │                      │   │
    │   │            └───────────────────────────────────────┘                      │   │
    │   │                                                                           │   │
    │   │   STATES:                                                                 │   │
    │   │   ┌─────────────────────────────────────────────────────────────────┐    │   │
    │   │   │  NOT SETUP  : No master password exists - first time setup       │    │   │
    │   │   │  LOCKED     : Vault encrypted - requires authentication          │    │   │
    │   │   │  UNLOCKED   : Vault decrypted - encryption key in RAM            │    │   │
    │   │   │  LOCKING    : Transition state - secure wipe in progress         │    │   │
    │   │   └─────────────────────────────────────────────────────────────────┘    │   │
    │   │                                                                           │   │
    │   │   TRANSITIONS:                                                            │   │
    │   │   ┌─────────────────────────────────────────────────────────────────┐    │   │
    │   │   │  setup_complete() : Creates master password and initializes vault│    │   │
    │   │   │  unlock()         : Verifies password, derives key, decrypts     │    │   │
    │   │   │  auto_lock()      : 5-minute inactivity timer triggers lock      │    │   │
    │   │   │  lock_vault()     : Manual lock, zero-fills key, clears RAM      │    │   │
    │   │   └─────────────────────────────────────────────────────────────────┘    │   │
    │   │                                                                           │   │
    │   └─────────────────────────────────────────────────────────────────────────┘   │
    │                                                                                  │
    └─────────────────────────────────────────────────────────────────────────────────┘
    """)
    print()


def main():
    """Main function to generate the complete UML documentation."""
    print_header()
    print_class_auth_manager()
    print("                              │")
    print("                              │ creates")
    print("                              ▼")
    print_class_encryption_provider()
    print("                              ▲")
    print("                              │ uses")
    print("                              │")
    print_class_storage_engine()
    print()
    print("                              ┌─────────────────────────────────────────┐")
    print("                              │                                         │")
    print("                              ▼                                         ▼")
    print_class_sentinel_auditor()
    print("                                                                         ")
    print("                              ◇─── SentinelsVaultApp ───◇                ")
    print("                              │                    │                     ")
    print("                              │                    │                     ")
    print("                              ▼                    ▼                     ")
    print("                        AuthManager         StorageEngine                ")
    print("                              │                    │                     ")
    print("                              │                    │                     ")
    print("                              ▼                    ▼                     ")
    print("                      EncryptionProvider    SentinelAuditor              ")
    print()
    
    print_relationships()
    print_database_schema()
    print_sequence_flow()
    print_state_machine()
    
    print()
    print("=" * 80)
    print("                    UML Documentation Complete")
    print("=" * 80)
    print()
    print("This diagram demonstrates:")
    print("  ✓ Object-Oriented Design (5 core classes)")
    print("  ✓ Singleton Pattern (SentinelAuditor)")
    print("  ✓ Composition & Dependency Relationships")
    print("  ✓ Database Schema in 3rd Normal Form")
    print("  ✓ Sequence Diagram for Login Flow")
    print("  ✓ State Machine for Vault Lifecycle")
    print()


if __name__ == "__main__":
    main()