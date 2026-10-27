"""Password-based key hierarchy.

    password + per-user salt --PBKDF2-HMAC-SHA256--> master (32 B)
        master --HMAC "auth"--> login verifier   (its SHA-256 is stored)
        master --HMAC "kek"---> key-encryption key (never stored)

    vault key (32 random bytes, one per user)
        stored only wrapped by the KEK with AES-256-GCM
        --HMAC "enc:<cipher>"--> AES-256 / DES / RC4-128 encryption keys
        --HMAC "mac:<cipher>"--> one HMAC-SHA256 key per cipher

Because the vault key is random and independent of the password, a password
change only re-wraps 32 bytes instead of re-encrypting every document.
"""

import hashlib
import hmac
from dataclasses import dataclass, field

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from . import ciphers, envelope

SALT_SIZE = 16
VAULT_KEY_SIZE = 32


def _label(key: bytes, label: str) -> bytes:
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def new_salt() -> bytes:
    return get_random_bytes(SALT_SIZE)


def derive_login_secrets(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Return (verifier_hash, kek). One slow PBKDF2 run serves both login and unwrapping."""
    master = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    verifier_hash = hashlib.sha256(_label(master, "auth")).digest()
    return verifier_hash, _label(master, "kek")


def wrap_vault_key(kek: bytes, vault_key: bytes, username: str) -> bytes:
    nonce = get_random_bytes(12)
    gcm = AES.new(kek, AES.MODE_GCM, nonce=nonce)
    gcm.update(b"vault-key|" + username.encode())
    ct, tag = gcm.encrypt_and_digest(vault_key)
    return nonce + ct + tag


def unwrap_vault_key(kek: bytes, wrapped: bytes, username: str) -> bytes:
    nonce, ct, tag = wrapped[:12], wrapped[12:-16], wrapped[-16:]
    gcm = AES.new(kek, AES.MODE_GCM, nonce=nonce)
    gcm.update(b"vault-key|" + username.encode())
    try:
        return gcm.decrypt_and_verify(ct, tag)
    except ValueError as exc:
        raise envelope.IntegrityError("vault key could not be unwrapped") from exc


@dataclass(frozen=True)
class VaultKeys:
    """Per-user subkeys derived from the vault key. Lives only in server memory."""

    vault_key: bytes = field(repr=False)

    @classmethod
    def generate(cls) -> "VaultKeys":
        return cls(get_random_bytes(VAULT_KEY_SIZE))

    def enc_key(self, cipher: str) -> bytes:
        return _label(self.vault_key, f"enc:{cipher}")[: ciphers.KEY_SIZES[cipher]]

    def mac_key(self, cipher: str) -> bytes:
        return _label(self.vault_key, f"mac:{cipher}")

    def seal(self, cipher: str, plaintext: bytes, context: str) -> bytes:
        return envelope.seal(cipher, self.enc_key(cipher), self.mac_key(cipher), plaintext, context)

    def open(self, cipher: str, sealed: bytes, context: str) -> bytes:
        return envelope.open_(cipher, self.enc_key(cipher), self.mac_key(cipher), sealed, context)
