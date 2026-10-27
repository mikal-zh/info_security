# PROJECT, 2026
# info_security
# File description:
# Raw cipher primitives: AES-256-CBC, DES-CBC and RC4-drop3072.

"""Raw cipher primitives: AES-256-CBC, DES-CBC and RC4-drop3072.

These functions only provide confidentiality. The application never calls
them directly; it uses `envelope.seal` and `envelope.open_`, which add the
HMAC that makes tampering detectable.
"""

import hashlib
import hmac

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CIPHERS = ("AES", "DES", "RC4")
KEY_SIZES = {"AES": 32, "DES": 8, "RC4": 16}
BLOCK_SIZES = {"AES": AES.block_size, "DES": DES.block_size}
NONCE_SIZES = {"AES": AES.block_size, "DES": DES.block_size, "RC4": 16}
RC4_DROP = 3072


def _check(cipher: str) -> None:
    """Raise ValueError for a cipher name this module does not implement."""
    if cipher not in CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")


def _cbc(cipher: str, key: bytes, iv: bytes):
    """Return a fresh CBC-mode cipher object for AES or DES."""
    module = AES if cipher == "AES" else DES
    return module.new(key, module.MODE_CBC, iv=iv)


def _rc4(key: bytes, nonce: bytes):
    """Return an RC4 cipher keyed for one message only.

    RC4 has no IV: reusing one key would reuse the keystream, and the XOR
    of two ciphertexts would equal the XOR of the plaintexts. Each message
    therefore uses HMAC-SHA256(key, nonce) as its key. The first 3072
    keystream bytes are dropped because early RC4 output is biased and
    correlated with the key (Fluhrer-Mantin-Shamir, Mantin-Shamir).
    """
    label = b"rc4-msg" + nonce
    digest = hmac.new(key, label, hashlib.sha256).digest()
    return ARC4.new(digest[: KEY_SIZES["RC4"]], drop=RC4_DROP)


def encrypt(cipher: str, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt and return (nonce, ciphertext).

    A fresh random nonce is drawn on every call: the CBC IV for AES and
    DES (with PKCS#7 padding), or the per-message key nonce for RC4.
    """
    _check(cipher)
    nonce = get_random_bytes(NONCE_SIZES[cipher])
    if cipher == "RC4":
        return nonce, _rc4(key, nonce).encrypt(plaintext)
    padded = pad(plaintext, BLOCK_SIZES[cipher])
    return nonce, _cbc(cipher, key, nonce).encrypt(padded)


def decrypt(cipher: str, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext produced by `encrypt` with the same nonce."""
    _check(cipher)
    if cipher == "RC4":
        return _rc4(key, nonce).decrypt(ciphertext)
    padded = _cbc(cipher, key, nonce).decrypt(ciphertext)
    return unpad(padded, BLOCK_SIZES[cipher])
