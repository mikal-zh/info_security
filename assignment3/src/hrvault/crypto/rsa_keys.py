# PROJECT, 2026
# info_security
# File description:
# RSA key pairs: generation, sealed storage and key transport with OAEP.

"""RSA key pairs: generation, sealed storage and key transport.

Every user owns an RSA key pair. The public key is public, so it is
stored in clear as a DER SubjectPublicKeyInfo. The private key is stored
as PKCS#8 DER sealed with the user's AES subkey (encrypt-then-MAC
envelope), so it can only be opened while its owner is logged in.

RSA-OAEP with SHA-256 transports the random key of a share to the user
who asked for it: only that user's private key can unwrap it.
"""

import hashlib

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from .envelope import IntegrityError
from .vault_keys import VaultKeys

PUBLIC_EXPONENT = 65537
PRIVATE_KEY_CIPHER = "AES"
FINGERPRINT_BYTES = 16


def generate(bits: int) -> RSA.RsaKey:
    """Create a fresh RSA key pair of the given modulus size."""
    return RSA.generate(bits, e=PUBLIC_EXPONENT)


def public_der(key: RSA.RsaKey) -> bytes:
    """The public half of `key` as a DER SubjectPublicKeyInfo."""
    return key.public_key().export_key(format="DER")


def seal_private(keys: VaultKeys, key: RSA.RsaKey, context: str) -> bytes:
    """Seal the PKCS#8 private key with the user's AES subkey."""
    der = key.export_key(format="DER", pkcs=8)
    return keys.seal(PRIVATE_KEY_CIPHER, der, context)


def open_private(keys: VaultKeys, sealed: bytes, context: str):
    """Verify, decrypt and load a private key sealed by `seal_private`."""
    der = keys.open(PRIVATE_KEY_CIPHER, sealed, context)
    return RSA.import_key(der)


def encrypt_for(public_key: bytes, data: bytes) -> bytes:
    """Encrypt a short secret for the holder of a DER public key."""
    key = RSA.import_key(public_key)
    return PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(data)


def decrypt_with(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    """Decrypt an OAEP ciphertext; IntegrityError if it is not for us."""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    try:
        return cipher.decrypt(ciphertext)
    except ValueError as exc:
        raise IntegrityError("RSA-OAEP decryption failed") from exc


def fingerprint(public_key: bytes) -> str:
    """Short SHA-256 fingerprint of a public key, in groups of 4 hex."""
    digest = hashlib.sha256(public_key).hexdigest()
    groups = []
    for start in range(0, FINGERPRINT_BYTES * 2, 4):
        groups.append(digest[start:start + 4])
    return ":".join(groups)


def key_bits(public_key: bytes) -> int:
    """Modulus size in bits of a DER public key."""
    return RSA.import_key(public_key).size_in_bits()
