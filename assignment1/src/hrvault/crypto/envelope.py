# PROJECT, 2026
# info_security
# File description:
# Authenticated envelope: cipher + HMAC-SHA256 (encrypt-then-MAC).

"""Authenticated envelope: cipher + HMAC-SHA256 (encrypt-then-MAC).

Stored format of one envelope:

    version (1) | cipher id (1) | nonce/IV | ciphertext | HMAC tag (32)

The tag covers the header, nonce and ciphertext, plus a *context* string
(for example ``user:7|field:nik``) that is not stored. A ciphertext copied
into another user's row or another field therefore fails verification
instead of decrypting. The tag is checked before any decryption or
unpadding, which also rules out CBC padding-oracle attacks.
"""

import hashlib
import hmac
from typing import NamedTuple

from . import ciphers

VERSION = 1
CIPHER_IDS = {"AES": 1, "DES": 2, "RC4": 3}
TAG_SIZE = 32
HEADER_SIZE = 2


class IntegrityError(Exception):
    """The envelope was modified, belongs elsewhere, or the key is wrong."""


class CipherKeys(NamedTuple):
    """The cipher name with its encryption key and its HMAC key."""

    cipher: str
    enc_key: bytes
    mac_key: bytes


def _tag(mac_key: bytes, context: str, body: bytes) -> bytes:
    """HMAC-SHA256 over the length-prefixed context and the envelope body."""
    ctx = context.encode()
    message = len(ctx).to_bytes(2, "big") + ctx + body
    return hmac.new(mac_key, message, hashlib.sha256).digest()


def seal(keys: CipherKeys, plaintext: bytes, context: str) -> bytes:
    """Encrypt then authenticate, returning the complete envelope."""
    nonce, ciphertext = ciphers.encrypt(keys.cipher, keys.enc_key, plaintext)
    body = bytes([VERSION, CIPHER_IDS[keys.cipher]]) + nonce + ciphertext
    return body + _tag(keys.mac_key, context, body)


def _verified_body(keys: CipherKeys, envelope: bytes, context: str) -> bytes:
    """Return the envelope body if its tag and header are valid.

    Raises IntegrityError for a short, modified or relocated envelope.
    """
    minimum = HEADER_SIZE + ciphers.NONCE_SIZES[keys.cipher] + TAG_SIZE
    if len(envelope) < minimum:
        raise IntegrityError("envelope too short")
    body, tag = envelope[:-TAG_SIZE], envelope[-TAG_SIZE:]
    if not hmac.compare_digest(tag, _tag(keys.mac_key, context, body)):
        raise IntegrityError("authentication tag mismatch")
    if body[:HEADER_SIZE] != bytes([VERSION, CIPHER_IDS[keys.cipher]]):
        raise IntegrityError("unexpected envelope header")
    return body


def open_(keys: CipherKeys, envelope: bytes, context: str) -> bytes:
    """Verify the tag, then decrypt and return the plaintext."""
    body = _verified_body(keys, envelope, context)
    nonce_end = HEADER_SIZE + ciphers.NONCE_SIZES[keys.cipher]
    nonce = body[HEADER_SIZE:nonce_end]
    return ciphers.decrypt(keys.cipher, keys.enc_key, nonce, body[nonce_end:])


def overhead(cipher: str, plaintext_len: int) -> int:
    """Bytes added on top of the plaintext (header, nonce, padding, tag)."""
    padding = 0
    if cipher in ciphers.BLOCK_SIZES:
        block = ciphers.BLOCK_SIZES[cipher]
        padding = block - plaintext_len % block
    return HEADER_SIZE + ciphers.NONCE_SIZES[cipher] + padding + TAG_SIZE
