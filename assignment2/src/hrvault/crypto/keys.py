# PROJECT, 2026
# info_security
# File description:
# Password-based key derivation and vault-key wrapping.

"""Password-based key hierarchy.

    password + per-user salt --PBKDF2-HMAC-SHA256--> master (32 B)
        master --HMAC "auth"--> login verifier   (its SHA-256 is stored)
        master --HMAC "kek"---> key-encryption key (never stored)

    vault key (32 random bytes, one per user)
        stored only wrapped by the KEK with AES-256-GCM

Because the vault key is random and independent of the password, a
password change only re-wraps 32 bytes instead of re-encrypting every
document. Per-cipher subkeys are derived in `vault_keys.py`.
"""

import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .envelope import IntegrityError

SALT_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


def label_key(key: bytes, label: str) -> bytes:
    """Derive an independent 32-byte subkey from `key` for `label`."""
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def new_salt() -> bytes:
    """Return a fresh random per-user salt."""
    return get_random_bytes(SALT_SIZE)


def derive_login_secrets(password: str, salt: bytes, iterations: int):
    """Return (verifier_hash, kek) from one slow PBKDF2 run.

    The same run serves both the login check and unwrapping the vault
    key, so a login costs a single PBKDF2 computation.
    """
    master = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                 iterations)
    verifier_hash = hashlib.sha256(label_key(master, "auth")).digest()
    return verifier_hash, label_key(master, "kek")


def _gcm(kek: bytes, nonce: bytes, username: str):
    """AES-256-GCM object whose associated data binds the key to a user."""
    gcm = AES.new(kek, AES.MODE_GCM, nonce=nonce)
    gcm.update(b"vault-key|" + username.encode())
    return gcm


def wrap_vault_key(kek: bytes, vault_key: bytes, username: str) -> bytes:
    """Encrypt the vault key under the KEK: nonce | ciphertext | tag."""
    nonce = get_random_bytes(GCM_NONCE_SIZE)
    ciphertext, tag = _gcm(kek, nonce, username).encrypt_and_digest(vault_key)
    return nonce + ciphertext + tag


def unwrap_vault_key(kek: bytes, wrapped: bytes, username: str) -> bytes:
    """Decrypt the vault key; raise IntegrityError on a wrong key or user."""
    nonce = wrapped[:GCM_NONCE_SIZE]
    ciphertext = wrapped[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
    tag = wrapped[-GCM_TAG_SIZE:]
    try:
        return _gcm(kek, nonce, username).decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError("vault key could not be unwrapped") from exc
