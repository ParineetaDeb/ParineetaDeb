# storage_engine.py
# MODULE 3: Data Management — The Storage Engine
# This module manages ALL interactions with the SQLite database.
# NEW: Password History Tracker added — TABLE 3: password_history

import sqlite3
import logging
import secrets
from datetime import datetime


# LOGGING SETUP
# ─────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
# Import from main (or use environment variable)
import main
DATABASE_FILE = str(main.get_vault_path())

# Maximum number of history entries stored per credential.
# When this limit is reached, the oldest entry is deleted automatically.
# This prevents the database from growing indefinitely.
MAX_HISTORY_PER_CREDENTIAL = 10


class StorageEngine:
    """
    Manages the SQLite database for SentinelsVault.
    Implementation: 3rd Normal Form (3NF) for Relational Integrity.

    Database Tables:
    ─────────────────────────────────────────
    TABLE 1: vault_config      → Master password hash and salt
    TABLE 2: credentials       → All current encrypted passwords
    TABLE 3: password_history  → Encrypted old passwords with timestamps
    ─────────────────────────────────────────
    """

    def __init__(self):
        """Initializes the database connection and ensures tables exist."""
        try:
            self.conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
            self.cursor = self.conn.cursor()

            # Enable WAL mode for high performance and crash resilience.
            # WAL = Write-Ahead Logging. Part of SQLite's ACID compliance.
            # It allows reads and writes to happen simultaneously without locking.
            self.cursor.execute("PRAGMA journal_mode=WAL")

            self._initialize_tables()
            logger.info("StorageEngine initialized successfully.")
        except sqlite3.Error as e:
            logger.critical(f"Database initialization failed: {e}")
            raise

    def _initialize_tables(self):
        """
        Creates all three database tables if they do not already exist.
        'CREATE TABLE IF NOT EXISTS' means this is safe to run every launch —
        it only creates the table the very first time.
        """

        # ── TABLE 1: vault_config (The Lock) ──
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_config (
                id          INTEGER PRIMARY KEY,
                salt        BLOB    NOT NULL,
                master_hash TEXT    NOT NULL,
                mfa_secret  TEXT,
                recovery_salt            BLOB,
                vault_key_enc_master     BLOB,
                vault_key_nonce_master   BLOB,
                vault_key_enc_recovery   BLOB,
                vault_key_nonce_recovery BLOB,
                mfa_enabled              INTEGER,
                mfa_secret_enc           BLOB,
                mfa_secret_nonce         BLOB,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Ensure older databases get the new columns too.
        self._migrate_vault_config_schema()

        # ── TABLE 2: credentials (The Active Vault) ──
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name           TEXT    NOT NULL,
                username            TEXT    NOT NULL,
                encrypted_password  BLOB    NOT NULL,
                iv                  BLOB    NOT NULL,
                category            TEXT    DEFAULT 'General',
                notes               TEXT,
                created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── TABLE 3: password_history (The Tracker) ──
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id           INTEGER NOT NULL,
                old_encrypted_password  BLOB    NOT NULL,
                old_iv                  BLOB    NOT NULL,
                changed_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                change_number           INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (credential_id)
                    REFERENCES credentials(id)
                    ON DELETE CASCADE
            )
        """)

        # ── TABLE 4: active_sessions (Future Feature - Cross-Device Sync) ──
        # This table is for future implementation of session tracking
        # and remote revocation capabilities.
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token   TEXT    UNIQUE NOT NULL,
                device_id       TEXT    NOT NULL,
                device_name     TEXT,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_revoked      INTEGER DEFAULT 0
            )
        """)

        # Enable foreign key enforcement
        self.cursor.execute("PRAGMA foreign_keys = ON")
        logger.info("Database schema verified/created. All 4 tables ready.")
            # ── TABLE 4: active_sessions (Remote Session Management) ──
        self.cursor.execute ("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_revoked INTEGER DEFAULT 0,
                kill_token TEXT
            )
        """)
        # ── TABLE: device_pairs (Cross-Device Heartbeat) ──
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT,
                pairing_code TEXT,
                is_active INTEGER DEFAULT 1,
                last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # ── TABLE: password_changes (Cross-Device Sync) ──
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_type TEXT NOT NULL,
                old_password TEXT NOT NULL,
                new_password TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                synced_to_devices INTEGER DEFAULT 0
            )
        """)
        
        self.conn.commit()  
    def _migrate_vault_config_schema(self):
        """
        Adds missing vault_config columns for existing DB files.

        Without this, CREATE TABLE IF NOT EXISTS won't update schema
        for users who already created the vault earlier.
        """
        expected = {
            "recovery_salt": "BLOB",
            "vault_key_enc_master": "BLOB",
            "vault_key_nonce_master": "BLOB",
            "vault_key_enc_recovery": "BLOB",
            "vault_key_nonce_recovery": "BLOB",
            "mfa_enabled": "INTEGER",
            "mfa_secret_enc": "BLOB",
            "mfa_secret_nonce": "BLOB",
        }

        self.cursor.execute("PRAGMA table_info(vault_config)")
        rows = self.cursor.fetchall()
        existing_cols = {r[1] for r in rows}

        for col, col_type in expected.items():
            if col not in existing_cols:
                logger.info(f"DB migration: adding column {col} to vault_config")
                self.cursor.execute(
                    f"ALTER TABLE vault_config ADD COLUMN {col} {col_type}"
                )

        self.conn.commit()

    # ─────────────────────────────────────────────
    # VAULT CONFIG OPERATIONS
    # ─────────────────────────────────────────────

    def is_vault_initialized(self) -> bool:
        """Checks if a master password has already been set up."""
        self.cursor.execute("SELECT COUNT(*) FROM vault_config")
        return self.cursor.fetchone()[0] > 0

    def save_vault_config(
        self,
        salt: bytes,
        master_hash: str,
        mfa_secret: str = None,
        recovery_salt: bytes = None,
        vault_key_enc_master: bytes = None,
        vault_key_nonce_master: bytes = None,
        vault_key_enc_recovery: bytes = None,
        vault_key_nonce_recovery: bytes = None,
        mfa_enabled: int = 0,
        mfa_secret_enc: bytes = None,
        mfa_secret_nonce: bytes = None,
    ):
        """Saves the initial security configuration for the vault."""
        query = """
            INSERT INTO vault_config (
                salt, master_hash, mfa_secret,
                recovery_salt,
                vault_key_enc_master, vault_key_nonce_master,
                vault_key_enc_recovery, vault_key_nonce_recovery,
                mfa_enabled,
                mfa_secret_enc, mfa_secret_nonce
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.cursor.execute(
            query,
            (
                salt,
                master_hash,
                mfa_secret,
                recovery_salt,
                vault_key_enc_master,
                vault_key_nonce_master,
                vault_key_enc_recovery,
                vault_key_nonce_recovery,
                mfa_enabled,
                mfa_secret_enc,
                mfa_secret_nonce,
            ),
        )
        self.conn.commit()
        logger.info("Master configuration stored.")

    def get_vault_config(self):
        """Retrieves the salt and hash needed for login verification."""
        self.cursor.execute(
            """
            SELECT
                salt, master_hash, mfa_secret,
                recovery_salt,
                vault_key_enc_master, vault_key_nonce_master,
                vault_key_enc_recovery, vault_key_nonce_recovery,
                mfa_enabled,
                mfa_secret_enc, mfa_secret_nonce
            FROM vault_config
            LIMIT 1
            """
        )
        return self.cursor.fetchone()

    def update_master_rewrap(
        self,
        new_salt: bytes,
        new_master_hash: str,
        new_vault_key_enc_master: bytes,
        new_vault_key_nonce_master: bytes,
    ):
        """
        Updates only the Master-Password wrapper around the vault key.

        This is used by the Recovery Code flow:
        - VK stays the same
        - only the Master wrapper is replaced
        """
        self.cursor.execute(
            """
            UPDATE vault_config
            SET
                salt = ?,
                master_hash = ?,
                vault_key_enc_master = ?,
                vault_key_nonce_master = ?
            WHERE id = (SELECT id FROM vault_config LIMIT 1)
            """,
            (new_salt, new_master_hash, new_vault_key_enc_master, new_vault_key_nonce_master),
        )
        self.conn.commit()
        logger.info("Master password wrapper re-wrapped successfully.")

    # ─────────────────────────────────────────────
    # CREDENTIAL CRUD OPERATIONS
    # ─────────────────────────────────────────────

    def add_credential(self, site: str, user: str, pwd_blob: bytes,
                       iv: bytes, cat: str = "General", notes: str = ""):
        """
        CREATE: Adds a brand new encrypted credential entry.
        No history is created here because this is a new entry, not an update.
        """
        query = """INSERT INTO credentials
                       (site_name, username, encrypted_password, iv, category, notes)
                   VALUES (?, ?, ?, ?, ?, ?)"""
        self.cursor.execute(query, (site, user, pwd_blob, iv, cat, notes))
        self.conn.commit()
        logger.info(f"Credential added for: {site}")

    def get_all_credentials(self):
        """READ: Fetches all stored entries for the UI list."""
        self.cursor.execute(
            "SELECT * FROM credentials ORDER BY site_name ASC")
        return self.cursor.fetchall()

    def get_credential_by_id(self, cred_id: int):
        """
        READ: Fetches one specific credential using its unique ID.
        Used when the user clicks 'View' on a specific entry.
        Returns a single tuple or None if not found.
        """
        self.cursor.execute(
            "SELECT * FROM credentials WHERE id = ?", (cred_id,))
        return self.cursor.fetchone()

    def update_credential(self, cred_id: int, site: str, user: str,
                          pwd_blob: bytes, iv: bytes, cat: str, notes: str):
        """
        UPDATE: Modifies an existing credential.

        IMPORTANT — History Tracking happens HERE automatically.
        Before updating, this method:
        1. Fetches the CURRENT (old) encrypted password from the database
        2. Saves it to password_history with a timestamp
        3. Then performs the actual UPDATE

        This means every password change is permanently recorded.
        The user never has to think about it — it happens automatically.
        """
        # Step 1: Fetch the current password BEFORE overwriting it.
        # We need to save it to history first.
        current = self.get_credential_by_id(cred_id)

        if current:
            # current[3] = encrypted_password (the old one, about to be replaced)
            # current[4] = iv (the old IV used to encrypt it)
            old_encrypted_password = current[3]
            old_iv                 = current[4]

            # Step 2: Save the old password to history BEFORE updating.
            # This preserves the complete audit trail.
            self._save_to_history(cred_id, old_encrypted_password, old_iv)

        # Step 3: Now perform the actual UPDATE with the new password.
        query = """UPDATE credentials
                   SET site_name=?, username=?, encrypted_password=?,
                       iv=?, category=?, notes=?,
                       last_updated=CURRENT_TIMESTAMP
                   WHERE id=?"""
        self.cursor.execute(
            query, (site, user, pwd_blob, iv, cat, notes, cred_id))
        self.conn.commit()
        logger.info(f"Credential ID {cred_id} updated. Old password archived.")

    def delete_credential(self, cred_id: int):
        """
        DELETE: Removes a credential permanently.
        Because of ON DELETE CASCADE on password_history,
        all history entries for this credential are also deleted
        automatically by SQLite. No orphaned history records.
        """
        self.cursor.execute(
            "DELETE FROM credentials WHERE id=?", (cred_id,))
        self.conn.commit()
        logger.info(
            f"Credential ID {cred_id} and all its history removed.")

    def search_credentials(self, search_text: str):
        """SEARCH: Filters credentials by site name."""
        query = "SELECT * FROM credentials WHERE site_name LIKE ?"
        self.cursor.execute(query, (f"%{search_text}%",))
        return self.cursor.fetchall()

    # ─────────────────────────────────────────────
    # PASSWORD HISTORY OPERATIONS
    # These are the new methods for TABLE 3.
    # ─────────────────────────────────────────────

    def _save_to_history(self, credential_id: int,
                         old_encrypted_password: bytes, old_iv: bytes):
        """
        INTERNAL METHOD — saves one old password to the history table.
        Called automatically by update_credential() — never called directly
        from the UI. The underscore prefix signals it is internal.

        credential_id:         The ID of the credential being updated
        old_encrypted_password: The AES-256 ciphertext of the old password
        old_iv:                The nonce/IV used to encrypt the old password

        After saving, it calls _enforce_history_limit() to ensure we never
        store more than MAX_HISTORY_PER_CREDENTIAL entries per credential.
        """
        # First, find out what change_number this should be.
        # Count existing history entries for this credential and add 1.
        self.cursor.execute("""
            SELECT COUNT(*) FROM password_history
            WHERE credential_id = ?
        """, (credential_id,))
        count         = self.cursor.fetchone()[0]
        change_number = count + 1   # e.g., if 3 entries exist, this is change #4

        # Insert the old password into the history table
        self.cursor.execute("""
            INSERT INTO password_history
                (credential_id, old_encrypted_password, old_iv, change_number)
            VALUES (?, ?, ?, ?)
        """, (credential_id, old_encrypted_password, old_iv, change_number))

        self.conn.commit()

        # Enforce the maximum history limit to keep the database lean
        self._enforce_history_limit(credential_id)

        logger.info(
            f"Password history saved for credential ID {credential_id}. "
            f"Change #{change_number}.")

    def _enforce_history_limit(self, credential_id: int):
        """
        INTERNAL METHOD — keeps history entries within the allowed limit.
        If more than MAX_HISTORY_PER_CREDENTIAL entries exist for one
        credential, the OLDEST ones are deleted automatically.

        Example: If MAX = 10 and there are now 11 entries,
        the oldest entry (lowest ID) is deleted, keeping only the 10 most recent.

        This prevents the database from growing infinitely over time.
        """
        self.cursor.execute("""
            SELECT COUNT(*) FROM password_history
            WHERE credential_id = ?
        """, (credential_id,))
        count = self.cursor.fetchone()[0]

        if count > MAX_HISTORY_PER_CREDENTIAL:
            # Calculate how many excess entries exist
            excess = count - MAX_HISTORY_PER_CREDENTIAL

            # Delete the oldest entries (smallest IDs = oldest records)
            self.cursor.execute("""
                DELETE FROM password_history
                WHERE id IN (
                    SELECT id FROM password_history
                    WHERE credential_id = ?
                    ORDER BY id ASC
                    LIMIT ?
                )
            """, (credential_id, excess))

            self.conn.commit()
            logger.info(
                f"History limit enforced: removed {excess} oldest "
                f"entries for credential ID {credential_id}.")

    def get_password_history(self, credential_id: int) -> list:
        """
        READ: Fetches all history entries for one specific credential.
        Returns them in reverse chronological order — most recent first.
        This is what the UI calls to display the history panel.

        Returns a list of tuples:
        (id, credential_id, old_encrypted_password, old_iv,
         changed_at, change_number)
        """
        self.cursor.execute("""
            SELECT id, credential_id, old_encrypted_password,
                   old_iv, changed_at, change_number
            FROM password_history
            WHERE credential_id = ?
            ORDER BY change_number DESC
        """, (credential_id,))
        results = self.cursor.fetchall()
        logger.info(
            f"Retrieved {len(results)} history entries "
            f"for credential ID {credential_id}.")
        return results

    def get_history_count(self, credential_id: int) -> int:
        """
        Returns the total number of password changes recorded
        for a specific credential.
        Used by the UI to show a badge like 'History: 4 changes'.
        """
        self.cursor.execute("""
            SELECT COUNT(*) FROM password_history
            WHERE credential_id = ?
        """, (credential_id,))
        return self.cursor.fetchone()[0]

    def get_all_history_summary(self) -> list:
        """
        READ: Fetches a summary of ALL history entries across all credentials.
        Joins password_history with credentials to show site names.
        Used for a vault-wide history overview if needed.

        Returns list of tuples:
        (site_name, username, changed_at, change_number)
        """
        self.cursor.execute("""
            SELECT
                c.site_name,
                c.username,
                h.changed_at,
                h.change_number
            FROM password_history h
            JOIN credentials c ON h.credential_id = c.id
            ORDER BY h.changed_at DESC
        """)
        return self.cursor.fetchall()

    def close(self):
        """Cleanly closes the database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed.")
        # ═══════════════════════════════════════════════════════════
    # PASSWORD CHANGE SYNC (For Case 1 - Same Password)
    # ═══════════════════════════════════════════════════════════
    
    def record_password_change(self, account_type: str, old_password: str, new_password: str):
        """
        Record password changes for cross-device sync.
        """
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_type TEXT NOT NULL,
                old_password TEXT NOT NULL,
                new_password TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                synced_to_devices INTEGER DEFAULT 0
            )
        """)
        
        self.cursor.execute("""
            INSERT INTO password_changes (account_type, old_password, new_password)
            VALUES (?, ?, ?)
        """, (account_type, old_password, new_password))
        self.conn.commit()
    
    def get_pending_changes(self) -> list:
        """
        Get unsynced password changes for other devices.
        """
        self.cursor.execute("""
            SELECT account_type, old_password, new_password, changed_at
            FROM password_changes
            WHERE synced_to_devices = 0
        """)
        return self.cursor.fetchall()
    
    def mark_changes_synced(self):
        """
        Mark all pending changes as synced.
        """
        self.cursor.execute("""
            UPDATE password_changes SET synced_to_devices = 1
            WHERE synced_to_devices = 0
        """)
        self.conn.commit()
        # ═══════════════════════════════════════════════════════════
    # REMOTE SESSION MANAGEMENT (Emergency Lock)
    # ═══════════════════════════════════════════════════════════
    
    def save_kill_token(self, kill_token: str) -> bool:
        """
        Save emergency kill token for remote revocation.
        """
        try:
            self.cursor.execute("""
                INSERT OR REPLACE INTO active_sessions (session_token, device_id, device_name, kill_token)
                VALUES (?, ?, ?, ?)
            """, ("kill_switch", "emergency", "Kill Switch", kill_token))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save kill token: {e}")
            return False
    
    def verify_kill_token(self, kill_token: str) -> bool:
        """
        Verify if kill token is valid.
        """
        self.cursor.execute("""
            SELECT kill_token FROM active_sessions 
            WHERE kill_token = ? AND is_revoked = 0
        """, (kill_token,))
        result = self.cursor.fetchone()
        return result is not None
    
    def revoke_all_sessions(self) -> int:
        """
        Revoke all active sessions.
        Returns number of sessions revoked.
        """
        self.cursor.execute("""
            UPDATE active_sessions 
            SET is_revoked = 1 
            WHERE is_revoked = 0
        """)
        self.conn.commit()
        return self.cursor.rowcount
    
    def mark_token_used(self, kill_token: str):
        """
        Mark kill token as used (one-time use).
        """
        self.cursor.execute("""
            UPDATE active_sessions 
            SET is_revoked = 1 
            WHERE kill_token = ?
        """, (kill_token,))
        self.conn.commit()
        # ═══════════════════════════════════════════════════════════
    # CROSS-DEVICE HEARTBEAT (Device Pairing)
    # ═══════════════════════════════════════════════════════════
    
    def create_device_pair(self, device_id: str, device_name: str, pairing_code: str) -> bool:
        """
        Create a paired relationship between laptop and phone.
        Both devices share a secret pairing code.
        """
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_pairs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pair_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_name TEXT,
                    pairing_code TEXT,
                    is_active INTEGER DEFAULT 1,
                    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Generate unique pair ID
            pair_id = secrets.token_hex(16)
            
            self.cursor.execute("""
                INSERT INTO device_pairs (pair_id, device_id, device_name, pairing_code)
                VALUES (?, ?, ?, ?)
            """, (pair_id, device_id, device_name, pairing_code))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to create device pair: {e}")
            return False
    
    def update_heartbeat(self, device_id: str) -> bool:
        """
        Update heartbeat timestamp for a device.
        Called every 30 seconds by each device.
        """
        try:
            self.cursor.execute("""
                UPDATE device_pairs 
                SET last_heartbeat = CURRENT_TIMESTAMP 
                WHERE device_id = ?
            """, (device_id,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to update heartbeat: {e}")
            return False
    
    def check_device_heartbeats(self) -> dict:
        """
        Check if all paired devices are alive.
        Returns status of each paired device.
        """
        self.cursor.execute("""
            SELECT device_id, device_name, last_heartbeat,
                   julianday('now') - julianday(last_heartbeat) as minutes_ago
            FROM device_pairs 
            WHERE is_active = 1
        """)
        results = self.cursor.fetchall()
        
        devices_status = {}
        for device_id, device_name, last_heartbeat, minutes_ago in results:
            is_alive = minutes_ago < 2  # Heartbeat within last 2 minutes
            devices_status[device_id] = {
                'name': device_name,
                'is_alive': is_alive,
                'minutes_since_heartbeat': round(minutes_ago, 1)
            }
        
        return devices_status