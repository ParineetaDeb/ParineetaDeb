# main.py
# THE LAUNCHER — Run this file to start SentinelsVault.
# Command: python main.py
# Add this at the top of main.py
import sys
import os
from pathlib import Path

def get_app_directory():
    """Get correct directory for storing vault on any platform"""
    if getattr(sys, 'frozen', False):
        # Running as compiled EXE/APP
        return Path(sys.executable).parent
    else:
        # Running as Python script
        return Path(__file__).parent

def get_vault_path():
    """Platform-specific vault storage location"""
    app_dir = get_app_directory()
    
    
    
    # For Windows/Mac/Linux, use app directory
    return app_dir / "sentinels_vault.db"

# Use this in StorageEngine
DATABASE_FILE = get_vault_path()

import sys
import os

def get_base_path():
    """Get the correct path whether running as script or EXE"""
    if getattr(sys, 'frozen', False):
        # Running as compiled EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

# Use this for database path in storage_engine.py
DATABASE_FILE = os.path.join(get_base_path(), "sentinels_vault.db")
import sys
import logging
import traceback
import signal
from pathlib import Path

# ─────────────────────────────────────────────
# STEP 1: DEPENDENCY CHECKER
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# STEP 1: DEPENDENCY CHECKER
# ─────────────────────────────────────────────

def check_dependencies():
    """
    Checks if all required libraries are installed before launching.
    If anything is missing, it tells the user exactly what to install.
    """
    required = {
        "customtkinter": "customtkinter",
        "cryptography":  "cryptography",
        "argon2":        "argon2-cffi",
        "pyotp":         "pyotp",
    }
    missing = []
    for module, pip_name in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(f"  → pip install {pip_name}")

    if missing:
        print("\n" + "=" * 55)
        print("  ❌ MISSING LIBRARIES — Cannot start SentinelsVault")
        print("=" * 55)
        print("  Run these commands in your terminal:")
        print("=" * 55)
        print("\n".join(missing))
        print("=" * 55 + "\n")
        sys.exit(1) # Exit with error code 1 (means something went wrong)
    # ─────────────────────────────────────────────
# STEP 2: ERROR REPORTING
# ─────────────────────────────────────────────

def generate_error_report(error: Exception, context: str = "") -> str:
    """
    Generates a professional error report for debugging.
    Creates a timestamped error report file in the logs directory.
    """
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"logs/error_report_{timestamp}.txt"
    try:
        Path("logs").mkdir(exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("SENTINELSVAULT - ERROR REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"Context: {context}\n")
            f.write(f"Error Type: {type(error).__name__}\n")
            f.write(f"Error Message: {str(error)}\n")
            f.write("\n" + "=" * 70 + "\n")
            f.write("TRACEBACK:\n")
            f.write("=" * 70 + "\n")
            f.write(traceback.format_exc())
            f.write("\n" + "=" * 70 + "\n")
            f.write("SYSTEM INFORMATION:\n")
            f.write("=" * 70 + "\n")
            f.write(f"Python Version: {sys.version}\n")
            f.write(f"Platform: {sys.platform}\n")
        
        return report_file
    except Exception:
        return "Could not create error report file"
# ─────────────────────────────────────────────
# STEP 2: MAIN FUNCTION
# ─────────────────────────────────────────────

def main():
    """
    The main entry point with enterprise-grade error handling.
    """
    # 1. Check libraries first
    check_dependencies()
    
    # 2. Set up logging (import after dependency check)
    from logging_config import setup_logging, log_security_event
    
    logger = None
    try:
        logger = setup_logging(log_level=logging.INFO, console_output=True)
        logger.info("SentinelsVault application starting...")
    except Exception as e:
        print(f"⚠️  Warning: Could not initialize logging: {e}")
        # Fallback to basic logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
    
    # 3. Import and launch the GUI
    try:
        from app_ui import SentinelsVaultApp
        
        logger.info("GUI module imported successfully")
        
        # Create the main window
        app = SentinelsVaultApp()
        logger.info("SentinelsVaultApp instance created")
        log_security_event("SYSTEM", "APPLICATION_START", "SUCCESS")
        
        # Start the event loop
        app.mainloop()
        
        logger.info("Application closed normally")
        log_security_event("SYSTEM", "APPLICATION_EXIT", "SUCCESS")
        
    except ImportError as e:
        logger.critical(f"Failed to import GUI module: {e}")
        print(f"\n❌ CRITICAL ERROR: Could not import app_ui.py")
        print(f"   Make sure all project files are in the same directory.")
        print(f"   Error: {e}")
        sys.exit(1)
        
    except Exception as e:
        # Log the error
        logger.critical(f"Application crashed: {str(e)}")
        logger.critical(traceback.format_exc())
        log_security_event("SYSTEM", "APPLICATION_CRASH", "FAILURE", str(e))
        
        # Generate error report
        report_file = generate_error_report(e, "Application Runtime")
        
        # Show user-friendly message
        print("\n" + "=" * 60)
        print("  ❌ SENTINELSVAULT ENCOUNTERED AN ERROR")
        print("=" * 60)
        print(f"  Error: {type(e).__name__}: {str(e)}")
        print(f"\n  An error report has been saved to:")
        print(f"  {report_file}")
        print("\n  Please share this file with technical support.")
        print("=" * 60 + "\n")
        
        # Ask if user wants to see details
        try:
            show_details = input("Show technical details? (y/N): ").lower() == 'y'
            if show_details:
                print("\n" + traceback.format_exc())
        except:
            pass
        
        sys.exit(1)
    
    finally:
        if logger:
            logger.info("SentinelsVault session ended")
            logger.info("=" * 60)
    import signal

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\n\n🛡️  SentinelsVault shutting down gracefully...")
    logging.info("Received shutdown signal, cleaning up...")
    sys.exit(0)

# Register signal handler (add before app.mainloop())
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
# ─────────────────────────────────────────────
# STEP 3: ENTRY GUARD
# ─────────────────────────────────────────────
# This means: only run main() if THIS file is
# being executed directly (not imported elsewhere).
# Standard Python best practice — always include this.

if __name__ == "__main__":
    main()