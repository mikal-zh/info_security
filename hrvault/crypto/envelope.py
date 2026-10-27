"""Authenticated envelope: cipher + HMAC-SHA256 (encrypt-then-MAC).

Stored format of one envelope:

    version (1) | cipher id (1) | nonce/IV | ciphertext | HMAC-SHA256 tag (32)

The tag covers the header, nonce and ciphertext, plus a *context* string
(for example ``user:7|field:nik``) that is not stored. Binding the context
means a ciphertext copied into another user's row or another field fails
verification instead of decrypting.

The tag is checked before any decryption or unpadding, which also rules out
CBC padding-oracle attacks.
"""

import hashlib
import hmac

from . import ciphers

VERSION = 1
CIPHER_IDS = {"AES": 1, "DES": 2, "RC4": 3}
CIPHER_NAMES = {v: k for k, v in CIPHER_IDS.items()}
TAG_SIZE = 32
HEADER_SIZE = 2


class IntegrityError(Exception):
    """The envelope was modified, belongs elsewhere, or the key is wrong."""


def _tag(mac_key: bytes, context: str, body: bytes) -> bytes:
    ctx = context.encode()
    msg = len(ctx).to_bytes(2, "big") + ctx + body
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def seal(cipher: str, enc_key: bytes, mac_key: bytes, plaintext: bytes, context: str) -> bytes:
    nonce, ct = ciphers.encrypt(cipher, enc_key, plaintext)
    body = bytes([VERSION, CIPHER_IDS[cipher]]) + nonce + ct
    return body + _tag(mac_key, context, body)


def open_(cipher: str, enc_key: bytes, mac_key: bytes, envelope: bytes, context: str) -> bytes:
    nonce_size = ciphers.NONCE_SIZES[cipher]
    if len(envelope) < HEADER_SIZE + nonce_size + TAG_SIZE:
        raise IntegrityError("envelope too short")
    body, tag = envelope[:-TAG_SIZE], envelope[-TAG_SIZE:]
    if not hmac.compare_digest(tag, _tag(mac_key, context, body)):
        raise IntegrityError("authentication tag mismatch")
    if body[0] != VERSION or CIPHER_NAMES.get(body[1]) != cipher:
        raise IntegrityError("unexpected envelope header")
    nonce = body[HEADER_SIZE : HEADER_SIZE + nonce_size]
    return ciphers.decrypt(cipher, enc_key, nonce, body[HEADER_SIZE + nonce_size :])


def overhead(cipher: str, plaintext_len: int) -> int:
    """Bytes added on top of the plaintext (header + nonce + padding + tag)."""
    block = {"AES": 16, "DES": 8}.get(cipher)
    padding = block - plaintext_len % block if block else 0
    return HEADER_SIZE + ciphers.NONCE_SIZES[cipher] + padding + TAG_SIZE
