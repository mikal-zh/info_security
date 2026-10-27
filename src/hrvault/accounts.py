"""Registration, login and password change on top of the key hierarchy."""

import hmac
import re
import sqlite3

from .crypto import IntegrityError, VaultKeys, keys

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LENGTH = 10

# Used to spend the same PBKDF2 time for unknown usernames, so response time
# does not reveal which employee numbers exist.
_DUMMY_SALT = bytes(keys.SALT_SIZE)


class AccountError(Exception):
    pass


def validate_new_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f"Pick a password of at least {MIN_PASSWORD_LENGTH} characters. A short sentence works well.")


def register(conn: sqlite3.Connection, username: str, password: str, iterations: int) -> int:
    if not USERNAME_RE.match(username):
        raise AccountError("Your employee number should be 3 to 32 characters: letters, digits, '.', '_' or '-'.")
    validate_new_password(password)
    salt = keys.new_salt()
    verifier, kek = keys.derive_login_secrets(password, salt, iterations)
    vault = VaultKeys.generate()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, salt, iterations, verifier, wrapped_key) VALUES (?, ?, ?, ?, ?)",
            (username, salt, iterations, verifier, keys.wrap_vault_key(kek, vault.vault_key, username)),
        )
    except sqlite3.IntegrityError as exc:
        raise AccountError("That employee number already has an account. Try logging in instead.") from exc
    conn.commit()
    return cur.lastrowid


def login(conn: sqlite3.Connection, username: str, password: str, iterations: int) -> tuple[int, VaultKeys] | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        keys.derive_login_secrets(password, _DUMMY_SALT, iterations)
        return None
    verifier, kek = keys.derive_login_secrets(password, row["salt"], row["iterations"])
    if not hmac.compare_digest(verifier, row["verifier"]):
        return None
    vault_key = keys.unwrap_vault_key(kek, row["wrapped_key"], row["username"])
    return row["id"], VaultKeys(vault_key)


def change_password(conn: sqlite3.Connection, user_id: int, old: str, new: str, iterations: int) -> None:
    """Re-wrap the same vault key under a new password; no document is re-encrypted."""
    validate_new_password(new)
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    verifier, kek = keys.derive_login_secrets(old, row["salt"], row["iterations"])
    if not hmac.compare_digest(verifier, row["verifier"]):
        raise AccountError("Your current password isn't right.")
    try:
        vault_key = keys.unwrap_vault_key(kek, row["wrapped_key"], row["username"])
    except IntegrityError as exc:
        raise AccountError("We couldn't unlock your stored key: it failed its integrity check.") from exc
    salt = keys.new_salt()
    new_verifier, new_kek = keys.derive_login_secrets(new, salt, iterations)
    conn.execute(
        "UPDATE users SET salt = ?, iterations = ?, verifier = ?, wrapped_key = ? WHERE id = ?",
        (salt, iterations, new_verifier, keys.wrap_vault_key(new_kek, vault_key, row["username"]), user_id),
    )
    conn.commit()
