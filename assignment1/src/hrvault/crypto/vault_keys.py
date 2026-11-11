# PROJECT, 2026
# info_security
# File description:
# Per-user subkeys for AES, DES and RC4, derived from the vault key.

"""Per-user subkeys derived from the vault key.

    vault key --HMAC "enc:<cipher>"--> AES-256 / DES / RC4-128 key
              --HMAC "mac:<cipher>"--> one HMAC-SHA256 key per cipher

A `VaultKeys` object lives only in server memory while the user is
logged in.
"""

from dataclasses import dataclass, field

from Crypto.Random import get_random_bytes

from . import ciphers, envelope
from .keys import label_key

VAULT_KEY_SIZE = 32


@dataclass(frozen=True)
class VaultKeys:
    """Holds the vault key and derives the per-cipher keys from it."""

    vault_key: bytes = field(repr=False)

    @classmethod
    def generate(cls) -> "VaultKeys":
        """Create keys from a fresh random vault key."""
        return cls(get_random_bytes(VAULT_KEY_SIZE))

    def cipher_keys(self, cipher: str) -> envelope.CipherKeys:
        """Encryption and MAC keys for one cipher."""
        enc_key = label_key(self.vault_key, f"enc:{cipher}")
        return envelope.CipherKeys(
            cipher,
            enc_key[: ciphers.KEY_SIZES[cipher]],
            label_key(self.vault_key, f"mac:{cipher}"),
        )

    def seal(self, cipher: str, plaintext: bytes, context: str) -> bytes:
        """Seal `plaintext` with the given cipher, bound to `context`."""
        return envelope.seal(self.cipher_keys(cipher), plaintext, context)

    def open(self, cipher: str, sealed: bytes, context: str) -> bytes:
        """Verify and decrypt an envelope sealed with `seal`."""
        return envelope.open_(self.cipher_keys(cipher), sealed, context)
