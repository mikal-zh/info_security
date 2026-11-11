# PROJECT, 2026
# info_security
# File description:
# RSA signatures, PKCS#1 v1.5 with SHA-256, written out by hand.

"""RSA signatures (RSASSA-PKCS1-v1_5 with SHA-256, RFC 8017 §8.2).

Signing a message M with a private key (n, d):

    H  = SHA-256(M)
    T  = DigestInfo(sha256, H)            (fixed 19-byte prefix | H)
    EM = 0x00 | 0x01 | 0xFF ... 0xFF | 0x00 | T     (k bytes, k = |n|)
    S  = EM ^ d mod n                      (RSA private-key operation)

Verifying S with the public key (n, e) recomputes EM' = S ^ e mod n and
compares it with the expected encoding. The library is only used for the
SHA-256 hash and to hold the key numbers.
"""

import hashlib
import hmac

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
MIN_PADDING = 8


class SignatureError(Exception):
    """The signature does not match the message and public key."""


def _modulus_bytes(key) -> int:
    """Length k of the modulus in bytes."""
    return (key.n.bit_length() + 7) // 8


def encode(message: bytes, size: int) -> bytes:
    """EMSA-PKCS1-v1_5 encoding of SHA-256(message) on `size` bytes."""
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding = size - len(digest_info) - 3
    if padding < MIN_PADDING:
        raise ValueError("RSA modulus too short for SHA-256")
    return b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info


def sign(private_key, message: bytes) -> bytes:
    """Signature of `message` with an RSA private key."""
    size = _modulus_bytes(private_key)
    encoded = int.from_bytes(encode(message, size), "big")
    signature = pow(encoded, private_key.d, private_key.n)
    return signature.to_bytes(size, "big")


def verify(public_key, message: bytes, signature: bytes) -> None:
    """Check a signature; raise SignatureError if it does not match."""
    size = _modulus_bytes(public_key)
    if len(signature) != size:
        raise SignatureError("signature length differs from the modulus")
    value = int.from_bytes(signature, "big")
    if value >= public_key.n:
        raise SignatureError("signature out of range")
    recovered = pow(value, public_key.e, public_key.n).to_bytes(size, "big")
    if not hmac.compare_digest(recovered, encode(message, size)):
        raise SignatureError("signature does not match the message")
