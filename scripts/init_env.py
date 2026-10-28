"""Create private, random demo secrets once; never overwrite existing keys."""
import argparse
import base64
import os
from pathlib import Path
import secrets

parser = argparse.ArgumentParser()
parser.add_argument("--path", default=".env")
args = parser.parse_args()
path = Path(args.path)
path.parent.mkdir(parents=True, exist_ok=True)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print(f"Using existing {path}; keys unchanged.")
else:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(f"JWT_SECRET={secrets.token_urlsafe(48)}\n"
                     f"FERNET_KEY={base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}\n"
                     "DATABASE_URL=sqlite:///./data/medical.db\nAPP_TIMEZONE=Asia/Qyzylorda\n")
    print(f"Created {path} with random secrets.")
