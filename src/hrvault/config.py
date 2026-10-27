# PROJECT, 2026
# info_security
# File description:
# Application configuration.

"""Application configuration, overridable with environment variables."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Config:
    """Default Flask settings for the onboarding vault."""

    DATA_DIR = Path(os.environ.get("HRVAULT_DATA_DIR",
                                   PROJECT_ROOT / "instance"))

    PBKDF2_ITERATIONS = int(os.environ.get("HRVAULT_PBKDF2_ITERATIONS",
                                           600_000))

    SESSION_IDLE_SECONDS = 30 * 60

    MAX_CONTENT_LENGTH = 100 * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # The cookie only carries an opaque session token, never key material,
    # so a per-process secret is enough: a restart wipes the keys anyway.
    SECRET_KEY = os.urandom(32)
