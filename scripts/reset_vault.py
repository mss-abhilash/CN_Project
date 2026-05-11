import os
import shutil
from pathlib import Path

def reset_vault():
    print("=" * 60)
    print("  IoT SECURE NETWORK: VAULT RESET & CLEAN SLATE")
    print("=" * 60)

    # 1. Clear Database
    db_path = Path("database/iot_secure.db")
    if db_path.exists():
        print(f"[CLEANUP] Deleting persistent database: {db_path}")
        os.remove(db_path)
    else:
        print("[SKIP] Database already clean.")

    # 2. Clear Logs
    log_dir = Path("logs")
    if log_dir.exists():
        print(f"[CLEANUP] Clearing log directory: {log_dir}")
        shutil.rmtree(log_dir)
        os.makedirs(log_dir)
    else:
        os.makedirs(log_dir)
        print("[SETUP] Logs directory initialized.")

    # 3. Clear WireGuard Configs (if any)
    config_dir = Path("vpn/configs")
    if config_dir.exists():
        print(f"[CLEANUP] Clearing VPN config cache: {config_dir}")
        shutil.rmtree(config_dir)
        os.makedirs(config_dir)

    print("\n" + "=" * 60)
    print("  [SUCCESS] Vault reset complete. Backend will auto-init on next run.")
    print("=" * 60)

if __name__ == "__main__":
    reset_vault()
