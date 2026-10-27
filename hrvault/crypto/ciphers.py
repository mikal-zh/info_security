"""Raw cipher primitives: AES-256-CBC, DES-CBC and RC4-drop3072.

These functions only provide confidentiality. They must not be called
directly by the application; use `envelope.seal` / `envelope.open_`, which add
the HMAC that makes tampering detectable.
"""

import hashlib
import hmac

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CIPHERS = ("AES", "DES", "RC4")

KEY_SIZES = {"AES": 32, "DES": 8, "RC4": 16}

# Length of the per-message random value stored in front of the ciphertext:
# the CBC IV (one block) for AES/DES, a nonce for RC4.
NONCE_SIZES = {"AES": AES.block_size, "DES": DES.block_size, "RC4": 16}

# Discard the first 3072 keystream bytes: the early RC4 output is biased and
# correlated with the key (Fluhrer-Mantin-Shamir, Mantin-Shamir).
RC4_DROP = 3072


def _rc4_message_key(key: bytes, nonce: bytes) -> bytes:
    # RC4 has no IV. Reusing one key would reuse the keystream, so every
    # message gets its own key derived from the long-term key and a nonce.
    return hmac.new(key, b"rc4-msg" + nonce, hashlib.sha256).digest()[: KEY_SIZES["RC4"]]


def encrypt(cipher: str, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt and return (nonce, ciphertext). A fresh random nonce is used every call."""
    nonce = get_random_bytes(NONCE_SIZES[cipher])
    if cipher == "AES":
        ct = AES.new(key, AES.MODE_CBC, iv=nonce).encrypt(pad(plaintext, AES.block_size))
    elif cipher == "DES":
        ct = DES.new(key, DES.MODE_CBC, iv=nonce).encrypt(pad(plaintext, DES.block_size))
    elif cipher == "RC4":
        ct = ARC4.new(_rc4_message_key(key, nonce), drop=RC4_DROP).encrypt(plaintext)
    else:
        raise ValueError(f"unknown cipher {cipher!r}")
    return nonce, ct


def decrypt(cipher: str, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if cipher == "AES":
        return unpad(AES.new(key, AES.MODE_CBC, iv=nonce).decrypt(ciphertext), AES.block_size)
    if cipher == "DES":
        return unpad(DES.new(key, DES.MODE_CBC, iv=nonce).decrypt(ciphertext), DES.block_size)
    if cipher == "RC4":
        return ARC4.new(_rc4_message_key(key, nonce), drop=RC4_DROP).decrypt(ciphertext)
    raise ValueError(f"unknown cipher {cipher!r}")
