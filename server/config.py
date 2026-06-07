import json
import os
from pathlib import Path

class Settings:
    def __init__(self):
        # Default options
        self.SERVER_PORT = 8000
        self.JWT_SECRET = "change-me-in-production-very-secret-key-123456"
        self.JWT_EXPIRY_HOURS = 24
        self.RP_ID = "vchat-diogo.duckdns.org"
        self.RP_NAME = "VChat"
        self.DATABASE_URL = "sqlite+aiosqlite:////data/vchat.db"

        # Check if running in Home Assistant Add-on context
        options_path = Path("/data/options.json")
        if options_path.exists():
            try:
                with open(options_path, "r") as f:
                    options = json.load(f)
                    self.SERVER_PORT = int(options.get("server_port", self.SERVER_PORT))
                    self.JWT_SECRET = options.get("jwt_secret", self.JWT_SECRET)
                    self.RP_ID = options.get("rp_id", self.RP_ID)
                    self.RP_NAME = options.get("rp_name", self.RP_NAME)
            except Exception as e:
                print(f"Error loading Home Assistant options: {e}")
        else:
            # Fall back to env variables or defaults
            self.SERVER_PORT = int(os.getenv("SERVER_PORT", self.SERVER_PORT))
            self.JWT_SECRET = os.getenv("JWT_SECRET", self.JWT_SECRET)
            self.RP_ID = os.getenv("RP_ID", self.RP_ID)
            self.RP_NAME = os.getenv("RP_NAME", self.RP_NAME)
            # For local testing, put DB in current directory if /data doesn't exist
            if not os.path.exists("/data"):
                os.makedirs("./data", exist_ok=True)
                self.DATABASE_URL = "sqlite+aiosqlite:///./data/vchat.db"

        # Android Passkey origins look like: "android:apk-key-hash:<sha256-hash-of-signing-cert>"
        # In verification, we allow any origin starting with "android:apk-key-hash:" or matching the RP_ID.
        self.RP_ORIGINS = [
            f"https://{self.RP_ID}",
            f"http://{self.RP_ID}",
            f"http://{self.RP_ID}:{self.SERVER_PORT}",
            f"https://{self.RP_ID}:{self.SERVER_PORT}",
            "http://localhost",
            "http://localhost:8000",
            # Home Assistant add-on origins
            "http://homeassistant:8000",
            "https://vchat-diogo.duckdns.org",
        ]

_settings = None

def get_settings():
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
