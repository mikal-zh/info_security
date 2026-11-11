# PROJECT, 2026
# info_security
# File description:
# Storage of each user's RSA key pair.

"""Each user's RSA key pair, stored next to the account.

The public key is stored in clear so that other users can encrypt for
it. The private key is sealed with the owner's AES subkey and bound to
the context ``user:<id>|rsa-private-key``, so a sealed key copied onto
another account does not open.
"""

import sqlite3

from .crypto import rsa_keys
from .owner import Owner

PRIVATE_KEY_ITEM = "rsa-private-key"
INSERT_KEYS = """
INSERT INTO user_keys (user_id, public_key, private_key) VALUES (?, ?, ?)
"""


def _row(conn: sqlite3.Connection, user_id: int):
    """The user's key row, or None if the user has no key pair."""
    return conn.execute("SELECT * FROM user_keys WHERE user_id = ?",
                        (user_id,)).fetchone()


def public_key_of(conn: sqlite3.Connection, user_id: int) -> bytes | None:
    """The user's DER public key, or None if the user has no key pair."""
    row = _row(conn, user_id)
    if row is None:
        return None
    return row["public_key"]


def has_key_pair(conn: sqlite3.Connection, user_id: int) -> bool:
    """True when the user already owns a key pair."""
    return _row(conn, user_id) is not None


def create_key_pair(owner: Owner, bits: int) -> None:
    """Generate a key pair for the owner and store it."""
    key = rsa_keys.generate(bits)
    context = owner.context(PRIVATE_KEY_ITEM)
    sealed = rsa_keys.seal_private(owner.keys, key, context)
    owner.conn.execute(INSERT_KEYS, (owner.user_id, rsa_keys.public_der(key),
                                     sealed))
    owner.conn.commit()


def ensure_key_pair(owner: Owner, bits: int) -> bool:
    """Create the owner's key pair if missing; True if one was created."""
    if has_key_pair(owner.conn, owner.user_id):
        return False
    create_key_pair(owner, bits)
    return True


def load_private_key(owner: Owner):
    """Open the owner's private key; None if the owner has no key pair."""
    row = _row(owner.conn, owner.user_id)
    if row is None:
        return None
    context = owner.context(PRIVATE_KEY_ITEM)
    return rsa_keys.open_private(owner.keys, row["private_key"], context)


def key_info(conn: sqlite3.Connection, user_id: int) -> dict | None:
    """Fingerprint, size and creation date of the user's public key."""
    row = _row(conn, user_id)
    if row is None:
        return None
    public = row["public_key"]
    return {"fingerprint": rsa_keys.fingerprint(public),
            "bits": rsa_keys.key_bits(public),
            "created_at": row["created_at"]}
