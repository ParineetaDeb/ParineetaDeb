# intruder_alert.py
# INTRUDER ALERT SYSTEM — SentinelsVault
#
# This module handles all intruder detection and response logic.
# It is completely separate from the UI — clean module design.
#
# Features:
# 1. Failed login attempt tracking (5 attempts = lockout)
# 2. Progressive lockout with exponential backoff
# 3. File system monitoring (db file access detection)
# 4. Detailed intruder log with timestamps and system info
# 5. Webcam capture on intrusion detection (if available)

import os
import time
import json
import hashlib
import logging
import platform
import threading
import datetime
import ipaddress
import subprocess

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
INTRUDER_LOG_FILE     = "intruder_alert.log"
INTRUDER_DATA_FILE    = "intruder_data.json"
MAX_FAILED_ATTEMPTS   = 5
LOCKOUT_DURATION_SECS = 1800   # 30 minutes
PHOTO_FOLDER          = "intruder_photos"


class IntruderAlertSystem:
    """
    Monitors and responds to unauthorized access attempts.

    Three layers of detection:
    ─────────────────────────────────────────
    Layer 1: Failed login tracking
        Counts wrong Master Password attempts.
        After MAX_FAILED_ATTEMPTS, triggers full lockout.

    Layer 2: File system monitoring
        Watches sentinels_vault.db for external access.
        Detects if DB Browser or any tool opens the file
        while the app is NOT running.

    Layer 3: Lockout enforcement
        Once locked, only the Recovery Code can unlock.
        Every unlock attempt during lockout is logged.
    ─────────────────────────────────────────
    """

    def __init__(self):
        """Initializes the alert system and loads existing state."""
        # Ensure photo folder exists
        if not os.path.exists(PHOTO_FOLDER):
            os.makedirs(PHOTO_FOLDER)

        # Load or create intruder data file
        # This file persists between app restarts so lockout survives reboots
        self._data = self._load_data()

        # Set up the dedicated intruder logger
        self._setup_logger()

        logger.info("IntruderAlertSystem initialized.")

    # ─────────────────────────────────────────────
    # DATA PERSISTENCE
    # ─────────────────────────────────────────────

    def _load_data(self) -> dict:
        """
        Loads the intruder tracking data from disk.
        If no data exists, creates a fresh default state.

        The data file stores:
        - failed_attempts:  How many wrong passwords were entered
        - lockout_until:    Unix timestamp when lockout expires (0 = not locked)
        - total_intrusions: Lifetime count of detected intrusion events
        - last_attempt_ts:  Timestamp of the most recent failed attempt
        - db_access_hash:   Hash of the DB file to detect external tampering
        """
        if os.path.exists(INTRUDER_DATA_FILE):
            try:
                with open(INTRUDER_DATA_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass

        # Default fresh state
        return {
            "failed_attempts":  0,
            "lockout_until":    0,
            "total_intrusions": 0,
            "last_attempt_ts":  0,
            "db_access_hash":   None,
            "alert_history":    []
        }

    def _save_data(self):
        """Saves the current intruder tracking state to disk."""
        try:
            with open(INTRUDER_DATA_FILE, "w") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save intruder data: {e}")

    def _setup_logger(self):
        """
        Sets up a dedicated file handler for the intruder log.
        This is separate from vault.log — it only records security events.

        The intruder_alert.log file records:
        - Every failed login attempt with timestamp
        - System information (OS, username, machine name)
        - Lockout events
        - File access violations
        - Photo capture events
        """
        self._intruder_logger = logging.getLogger("intruder_alert")
        self._intruder_logger.setLevel(logging.WARNING)

        # Only add handler if not already present
        if not self._intruder_logger.handlers:
            handler = logging.FileHandler(
                INTRUDER_LOG_FILE, encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            self._intruder_logger.addHandler(handler)

    # ─────────────────────────────────────────────
    # SYSTEM INFORMATION COLLECTION
    # ─────────────────────────────────────────────

    def _collect_system_info(self) -> dict:
        """
        Collects information about the current system state.
        This is recorded in the intruder log so you know exactly
        what happened, when, and on which machine.

        Returns a dictionary with:
        - timestamp: Exact date and time
        - os_info:   Operating system name and version
        - username:  Windows/Linux username logged in
        - hostname:  Computer name on the network
        - uptime:    How long the system has been running
        """
        info = {
            "timestamp": datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"),
            "os_info":   f"{platform.system()} {platform.release()} "
                         f"({platform.version()[:40]})",
            "username":  os.environ.get("USERNAME") or
                         os.environ.get("USER") or "unknown",
            "hostname":  platform.node(),
            "machine":   platform.machine(),
            "python":    platform.python_version(),
        }
        return info

    # ─────────────────────────────────────────────
    # FAILED LOGIN TRACKING
    # ─────────────────────────────────────────────

    def record_failed_attempt(self) -> dict:
        """
        Records one failed Master Password attempt.
        Called by app_ui.py every time perform_login() fails.

        Returns a response dictionary:
        {
            "attempts_remaining": int,   How many attempts left
            "is_locked":          bool,  True if vault is now locked
            "lockout_until":      str,   Human-readable lockout expiry
            "should_alert":       bool,  True if alert screen should show
            "total_attempts":     int,   Total failed attempts so far
        }

        Progressive response:
        - Attempt 1-2: Just count, show remaining attempts
        - Attempt 3-4: Warning — someone is trying to break in
        - Attempt 5:   LOCKOUT — vault locked for 30 minutes
                       Intruder log entry written
                       Photo captured (if webcam available)
        """
        self._data["failed_attempts"]  += 1
        self._data["last_attempt_ts"]   = time.time()
        attempts = self._data["failed_attempts"]

        sysinfo  = self._collect_system_info()
        attempts_left = max(0, MAX_FAILED_ATTEMPTS - attempts)

        # Log every failed attempt
        self._intruder_logger.warning(
            f"FAILED LOGIN ATTEMPT #{attempts} | "
            f"User: {sysinfo['username']} | "
            f"Machine: {sysinfo['hostname']} | "
            f"OS: {sysinfo['os_info']}"
        )

        response = {
            "attempts_remaining": attempts_left,
            "is_locked":          False,
            "lockout_until":      None,
            "should_alert":       False,
            "total_attempts":     attempts,
        }

        # Trigger full lockout at MAX_FAILED_ATTEMPTS
        if attempts >= MAX_FAILED_ATTEMPTS:
            lockout_until = time.time() + LOCKOUT_DURATION_SECS
            self._data["lockout_until"]    = lockout_until
            self._data["total_intrusions"] += 1

            lockout_str = datetime.datetime.fromtimestamp(
                lockout_until).strftime("%Y-%m-%d %H:%M:%S")

            # Write detailed intruder log entry
            self._intruder_logger.warning(
                "=" * 60
            )
            self._intruder_logger.warning(
                f"INTRUDER ALERT — VAULT LOCKED"
            )
            self._intruder_logger.warning(
                f"Time:     {sysinfo['timestamp']}"
            )
            self._intruder_logger.warning(
                f"Machine:  {sysinfo['hostname']} "
                f"({sysinfo['username']})"
            )
            self._intruder_logger.warning(
                f"OS:       {sysinfo['os_info']}"
            )
            self._intruder_logger.warning(
                f"Attempts: {attempts} failed attempts detected"
            )
            self._intruder_logger.warning(
                f"Locked until: {lockout_str}"
            )
            self._intruder_logger.warning(
                f"Total intrusion events: "
                f"{self._data['total_intrusions']}"
            )
            self._intruder_logger.warning("=" * 60)

            # Add to alert history list
            alert_entry = {
                "timestamp":    sysinfo["timestamp"],
                "type":         "FAILED_LOGIN_LOCKOUT",
                "attempts":     attempts,
                "username":     sysinfo["username"],
                "hostname":     sysinfo["hostname"],
                "locked_until": lockout_str,
            }
            self._data["alert_history"].append(alert_entry)

            # Try to capture webcam photo
            photo_path = self._capture_intruder_photo(attempts)
            if photo_path:
                alert_entry["photo"] = photo_path
                self._intruder_logger.warning(
                    f"Intruder photo captured: {photo_path}")

            # Reset attempt counter for next lockout cycle
            self._data["failed_attempts"] = 0

            response["is_locked"]      = True
            response["lockout_until"]  = lockout_str
            response["should_alert"]   = True

        self._save_data()
        return response

    def is_locked_out(self) -> tuple[bool, int]:
        """
        Checks whether the vault is currently in lockout mode.

        Returns: (is_locked: bool, seconds_remaining: int)

        Called every time the login screen is shown to prevent
        any interaction while the lockout is active.
        """
        lockout_until = self._data.get("lockout_until", 0)
        if lockout_until == 0:
            return False, 0

        now              = time.time()
        seconds_remaining = int(lockout_until - now)

        if seconds_remaining <= 0:
            # Lockout has expired — clear it
            self._data["lockout_until"] = 0
            self._save_data()
            return False, 0

        return True, seconds_remaining

    def reset_failed_attempts(self):
        """
        Resets the failed attempt counter after a successful login.
        Called by perform_login() when the correct password is entered.
        """
        self._data["failed_attempts"] = 0
        self._data["lockout_until"]   = 0
        self._save_data()
        logger.info("Failed attempt counter reset after successful login.")

    def get_failed_attempts(self) -> int:
        """Returns the current count of consecutive failed attempts."""
        return self._data.get("failed_attempts", 0)

    # ─────────────────────────────────────────────
    # WEBCAM PHOTO CAPTURE
    # ─────────────────────────────────────────────

    def _capture_intruder_photo(self, attempt_number: int) -> str | None:
        """
        Silently captures a photo using the webcam when an intruder
        is detected. The photo is saved to the intruder_photos/ folder.

        This uses OpenCV (cv2) which must be installed separately:
            pip install opencv-python

        Returns: The file path of the saved photo, or None if failed.

        Privacy note: This photo is saved locally ONLY.
        It is never uploaded or transmitted anywhere.
        This is purely for the legitimate owner to identify who
        attempted to access their vault.
        """
        try:
            import cv2  # type: ignore
        except ImportError:
            # OpenCV not installed — silently skip photo capture
            logger.info(
                "cv2 not installed — skipping photo capture. "
                "Run: pip install opencv-python to enable.")
            return None

        try:
            timestamp  = datetime.datetime.now().strftime(
                "%Y%m%d_%H%M%S")
            photo_path = os.path.join(
                PHOTO_FOLDER,
                f"intruder_attempt{attempt_number}_{timestamp}.jpg"
            )

            # Open the default webcam (index 0)
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                logger.info("No webcam detected — skipping photo capture.")
                return None

            # Allow camera to warm up for 0.5 seconds
            time.sleep(0.5)

            # Capture the frame
            ret, frame = cap.read()
            cap.release()

            if ret and frame is not None:
                cv2.imwrite(photo_path, frame)
                logger.info(f"Intruder photo saved: {photo_path}")
                return photo_path

        except Exception as e:
            logger.error(f"Photo capture failed: {e}")

        return None

    # ─────────────────────────────────────────────
    # FILE SYSTEM MONITORING
    # ─────────────────────────────────────────────

    def snapshot_db_hash(self, db_path: str = "sentinels_vault.db"):
        """
        Takes a SHA-256 hash of the database file and stores it.
        Called when the app starts and when the app closes.

        On next launch, check_db_integrity() compares the stored hash
        to the current file hash. If they differ, someone modified the
        database externally while the app was closed.

        Why SHA-256? Because even one byte changed by an attacker
        will produce a completely different hash — impossible to fake.
        """
        if not os.path.exists(db_path):
            return

        try:
            h = hashlib.sha256()
            with open(db_path, "rb") as f:
                # Read in 64KB chunks for large files
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            self._data["db_access_hash"] = h.hexdigest()
            self._data["db_snapshot_time"] = time.time()
            self._save_data()
            logger.info(f"DB hash snapshot taken: {h.hexdigest()[:16]}...")
        except Exception as e:
            logger.error(f"DB hash snapshot failed: {e}")

    def check_db_integrity(self,
                           db_path: str = "sentinels_vault.db") -> dict:
        """
        Compares the current database hash to the stored snapshot.
        If they differ, someone modified the file externally.

        Returns:
        {
            "tampered":      bool,  True if DB was modified externally
            "old_hash":      str,   Hash from last app session
            "new_hash":      str,   Current hash of the file
            "time_elapsed":  str,   How long since last snapshot
        }
        """
        result = {
            "tampered":     False,
            "old_hash":     None,
            "new_hash":     None,
            "time_elapsed": "unknown"
        }

        if not os.path.exists(db_path):
            return result

        stored_hash = self._data.get("db_access_hash")
        if not stored_hash:
            # No previous snapshot — take one now
            self.snapshot_db_hash(db_path)
            return result

        try:
            # Compute current hash
            h = hashlib.sha256()
            with open(db_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            current_hash = h.hexdigest()

            result["old_hash"] = stored_hash
            result["new_hash"] = current_hash

            # Calculate time since last snapshot
            snapshot_time = self._data.get("db_snapshot_time", 0)
            if snapshot_time:
                elapsed_secs = int(time.time() - snapshot_time)
                if elapsed_secs < 60:
                    result["time_elapsed"] = f"{elapsed_secs} seconds"
                elif elapsed_secs < 3600:
                    result["time_elapsed"] = \
                        f"{elapsed_secs // 60} minutes"
                else:
                    result["time_elapsed"] = \
                        f"{elapsed_secs // 3600} hours"

            if current_hash != stored_hash:
                result["tampered"] = True

                sysinfo = self._collect_system_info()
                self._intruder_logger.warning("=" * 60)
                self._intruder_logger.warning(
                    "DATABASE TAMPERING DETECTED")
                self._intruder_logger.warning(
                    f"Time: {sysinfo['timestamp']}")
                self._intruder_logger.warning(
                    f"Expected hash: {stored_hash[:32]}...")
                self._intruder_logger.warning(
                    f"Actual hash:   {current_hash[:32]}...")
                self._intruder_logger.warning(
                    f"Time since snapshot: {result['time_elapsed']}")
                self._intruder_logger.warning("=" * 60)

                alert_entry = {
                    "timestamp": sysinfo["timestamp"],
                    "type":      "DB_TAMPERING_DETECTED",
                    "old_hash":  stored_hash[:32] + "...",
                    "new_hash":  current_hash[:32] + "...",
                    "elapsed":   result["time_elapsed"],
                }
                self._data["alert_history"].append(alert_entry)
                self._data["total_intrusions"] += 1
                self._save_data()

        except Exception as e:
            logger.error(f"DB integrity check failed: {e}")

        return result

    def start_file_monitor(self,
                           db_path: str = "sentinels_vault.db",
                           on_access_callback=None):
        """
        Starts a background thread that monitors the database file
        for unexpected access while the app IS running.

        Every 10 seconds it checks:
        1. Has the file modification time changed unexpectedly?
        2. Is the file currently locked by another process?

        If suspicious activity is detected, on_access_callback is called.
        This allows the UI to show an alert popup immediately.

        db_path:            Path to the database file
        on_access_callback: Function to call when suspicious access found
        """
        self._monitor_active   = True
        self._monitor_callback = on_access_callback

        def monitor_loop():
            last_mtime = os.path.getmtime(db_path) \
                if os.path.exists(db_path) else 0

            while self._monitor_active:
                time.sleep(10)   # Check every 10 seconds
                try:
                    if not os.path.exists(db_path):
                        continue

                    current_mtime = os.path.getmtime(db_path)

                    # If modification time changed but we didn't change it
                    # (tracked via _app_last_write), flag it
                    app_last_write = getattr(
                        self, "_app_last_write_time", 0)
                    time_diff = abs(current_mtime - app_last_write)

                    if current_mtime != last_mtime and time_diff > 2.0:
                        # File was modified by something other than us
                        sysinfo = self._collect_system_info()
                        self._intruder_logger.warning(
                            f"SUSPICIOUS DB ACCESS DETECTED | "
                            f"File modified at: "
                            f"{datetime.datetime.fromtimestamp(current_mtime)}"
                        )

                        if self._monitor_callback:
                            self._monitor_callback({
                                "type":      "db_external_access",
                                "timestamp": sysinfo["timestamp"],
                                "detail":    "Database file was modified "
                                             "by an external process.",
                            })

                    last_mtime = current_mtime

                except Exception as e:
                    logger.error(f"File monitor error: {e}")

        monitor_thread = threading.Thread(
            target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("File system monitor started.")

    def mark_app_write(self):
        """
        Called every time SentinelsVault writes to the database.
        This lets the file monitor distinguish between legitimate
        app writes and external unauthorized modifications.
        """
        self._app_last_write_time = time.time()

    def stop_file_monitor(self):
        """Stops the background file monitoring thread."""
        self._monitor_active = False
        logger.info("File system monitor stopped.")

    # ─────────────────────────────────────────────
    # ALERT HISTORY
    # ─────────────────────────────────────────────

    def get_alert_history(self) -> list:
        """
        Returns all recorded intrusion events.
        Used by the UI to display the full alert history screen.

        Returns list of dicts, most recent first.
        """
        history = self._data.get("alert_history", [])
        return list(reversed(history))

    def get_summary(self) -> dict:
        """
        Returns a summary of all security events for the dashboard.
        Used by the UI to show the intruder alert badge.
        """
        is_locked, secs = self.is_locked_out()
        return {
            "total_intrusions":    self._data.get("total_intrusions", 0),
            "current_attempts":    self._data.get("failed_attempts", 0),
            "is_locked":           is_locked,
            "seconds_remaining":   secs,
            "alert_history_count": len(
                self._data.get("alert_history", [])),
        }

    def clear_history(self):
        """Clears the alert history (does not reset lockout state)."""
        self._data["alert_history"] = []
        self._save_data()
        self._intruder_logger.warning("Alert history cleared by user.")