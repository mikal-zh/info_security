import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Config:
    DATA_DIR = Path(os.environ.get("HRVAULT_DATA_DIR", PROJECT_ROOT / "instance"))

    # OWASP (2023) guidance for PBKDF2-HMAC-SHA256.
    PBKDF2_ITERATIONS = int(os.environ.get("HRVAULT_PBKDF2_ITERATIONS", 600_000))

    # Unwrapped vault keys are dropped after this much inactivity.
    SESSION_IDLE_SECONDS = 30 * 60

    # Largest upload accepted (an onboarding video is typically 20-60 MB).
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # The cookie only carries an opaque session token, never key material, so a
    # per-process secret is enough: a restart wipes the in-memory keys anyway.
    SECRET_KEY = os.urandom(32)
