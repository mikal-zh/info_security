# PROJECT, 2026
# info_security
# File description:
# Importing a user's own RSA private key instead of generating one.

"""Importing a user's own RSA private key instead of generating one.

The key may be PEM (PKCS#1 or PKCS#8) or DER, optionally protected by a
passphrase. It must be a private RSA key of at least 2048 bits. Once
imported it is sealed exactly like a generated key, and a certificate
is issued for it.
"""

from Crypto.PublicKey import RSA

from . import keypairs
from .owner import Owner

MIN_IMPORT_BITS = 2048
MAX_KEY_FILE_SIZE = 64 * 1024
UNREADABLE = ("We couldn't read that key. Is it an RSA private key, with "
              "the right passphrase?")


class KeyImportError(Exception):
    """A user-facing reason why a key file was refused."""


def read_private_key(data: bytes, passphrase: str) -> RSA.RsaKey:
    """Load and check a private key file; KeyImportError if unusable."""
    if not data or len(data) > MAX_KEY_FILE_SIZE:
        raise KeyImportError("Pick a PEM or DER key file first.")
    try:
        key = RSA.import_key(data, passphrase or None)
    except (ValueError, IndexError, TypeError) as exc:
        raise KeyImportError(UNREADABLE) from exc
    if not key.has_private():
        raise KeyImportError("That's a public key. We need the private "
                             "half to sign for you.")
    if key.size_in_bits() < MIN_IMPORT_BITS:
        raise KeyImportError(f"That key is too short: use at least "
                             f"{MIN_IMPORT_BITS} bits.")
    return key


def import_key_pair(owner: Owner, data: bytes, passphrase: str) -> None:
    """Store the user's own key, if they do not have a key pair yet."""
    if keypairs.public_key_of(owner.conn, owner.user_id) is not None:
        raise KeyImportError("You already have a key pair.")
    key = read_private_key(data, passphrase)
    keypairs.store_key_pair(owner, key, "imported")
