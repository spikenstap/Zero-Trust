import os
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    fernet_key: str
    database_url: str = "sqlite:///./data/medical.db"
    timezone: str = "Asia/Qyzylorda"

    @classmethod
    def from_env(cls):
        load_dotenv(Path(os.getenv("ENV_FILE", ".env")), override=False)
        secret = os.getenv("JWT_SECRET", "")
        key = os.getenv("FERNET_KEY", "")
        if len(secret) < 32 or secret.startswith("REPLACE_"):
            raise RuntimeError("JWT_SECRET must be random and at least 32 characters. Run python scripts/init_env.py")
        try:
            Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Invalid FERNET_KEY. Run python scripts/init_env.py") from exc
        timezone = os.getenv("APP_TIMEZONE", "Asia/Qyzylorda")
        ZoneInfo(timezone)
        return cls(secret, key, os.getenv("DATABASE_URL", cls.database_url), timezone)
