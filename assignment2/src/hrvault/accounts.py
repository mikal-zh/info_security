# PROJECT, 2026
# info_security
# File description:
# Registration, login and password change.

"""Registration, login and password change on top of the key hierarchy."""

import hmac
import re
import sqlite3
from dataclasses import dataclass

from .crypto import IntegrityError, VaultKeys, keys

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LENGTH = 10
DUMMY_SALT = bytes(keys.SALT_SIZE)
INSERT_USER = """
INSERT INTO users (username, salt, iterations, verifier, wrapped_key)
VALUES (?, ?, ?, ?, ?)
"""
UPDATE_USER = """
UPDATE users SET salt = ?, iterations = ?, verifier = ?, wrapped_key = ?
WHERE id = ?
"""


class AccountError(Exception):
    """A user-facing reason why an account action was refused."""


@dataclass(frozen=True)
class Credentials:
    """An employee number with a password."""

    username: str
    password: str


def validate_new_password(password: str) -> None:
    """Refuse passwords shorter than MIN_PASSWORD_LENGTH."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(
            f"Pick a password of at least {MIN_PASSWORD_LENGTH} characters."
            " A short sentence works well.")


def _lock_row(creds: Credentials, vault_key: bytes, iterations: int):
    """Salt, iterations, verifier and wrapped vault key for a password."""
    salt = keys.new_salt()
    verifier, kek = keys.derive_login_secrets(creds.password, salt,
                                              iterations)
    wrapped = keys.wrap_vault_key(kek, vault_key, creds.username)
    return salt, iterations, verifier, wrapped


def register(conn: sqlite3.Connection, creds: Credentials,
             iterations: int) -> int:
    """Create a user with a fresh random vault key; return the user id."""
    if not USERNAME_RE.match(creds.username):
        raise AccountError(
            "Your employee number should be 3 to 32 characters: letters, "
            "digits, '.', '_' or '-'.")
    validate_new_password(creds.password)
    row = _lock_row(creds, VaultKeys.generate().vault_key, iterations)
    try:
        cur = conn.execute(INSERT_USER, (creds.username, *row))
    except sqlite3.IntegrityError as exc:
        raise AccountError("That employee number already has an account. "
                           "Try logging in instead.") from exc
    conn.commit()
    return cur.lastrowid


def _unlock(row, password: str) -> bytes | None:
    """Return the user's vault key, or None if the password is wrong.

    The verifier is compared in constant time before the vault key is
    unwrapped.
    """
    verifier, kek = keys.derive_login_secrets(password, row["salt"],
                                              row["iterations"])
    if not hmac.compare_digest(verifier, row["verifier"]):
        return None
    return keys.unwrap_vault_key(kek, row["wrapped_key"], row["username"])


def login(conn: sqlite3.Connection, creds: Credentials, iterations: int):
    """Return (user id, VaultKeys), or None for bad credentials.

    Unknown usernames still cost one PBKDF2 run, so response time does
    not reveal which employee numbers exist.
    """
    row = conn.execute("SELECT * FROM users WHERE username = ?",
                       (creds.username,)).fetchone()
    if row is None:
        keys.derive_login_secrets(creds.password, DUMMY_SALT, iterations)
        return None
    vault_key = _unlock(row, creds.password)
    if vault_key is None:
        return None
    return row["id"], VaultKeys(vault_key)


def change_password(conn: sqlite3.Connection, user_id: int,
                    passwords: tuple[str, str], iterations: int) -> None:
    """Re-wrap the vault key under (old, new); no document is re-encrypted."""
    old, new = passwords
    validate_new_password(new)
    row = conn.execute("SELECT * FROM users WHERE id = ?",
                       (user_id,)).fetchone()
    try:
        vault_key = _unlock(row, old)
    except IntegrityError as exc:
        raise AccountError("We couldn't unlock your stored key: it failed "
                           "its integrity check.") from exc
    if vault_key is None:
        raise AccountError("Your current password isn't right.")
    creds = Credentials(row["username"], new)
    conn.execute(UPDATE_USER, (*_lock_row(creds, vault_key, iterations),
                               user_id))
    conn.commit()
