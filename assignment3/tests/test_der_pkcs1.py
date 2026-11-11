# PROJECT, 2026
# info_security
# File description:
# DER encoding and hand-written PKCS#1 v1.5 signature tests.

"""DER encoding and hand-written PKCS#1 v1.5 signature tests."""

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from hrvault.crypto import der, pkcs1


@pytest.fixture(scope="module")
def key():
    """One RSA key shared by the signature tests."""
    return RSA.generate(1024)


@pytest.mark.parametrize("value, encoded", [
    (0, "020100"), (127, "02017f"), (128, "02020080"), (256, "02020100"),
])
def test_integer_encoding(value, encoded):
    """Integers are minimal and stay positive."""
    assert der.integer(value).hex() == encoded


def test_oid_and_long_length():
    """Multi-byte OID arcs and long-form lengths follow X.690."""
    assert der.oid("1.2.840.113549.1.1.11").hex() == \
        "06092a864886f70d01010b"
    long_value = der.tlv(der.OCTET_STRING, b"a" * 300)
    assert long_value[:4].hex() == "0482012c"
    assert der.read(long_value).content == b"a" * 300


def test_decoder_reads_nested_values():
    """children() splits a SEQUENCE back into its items."""
    encoded = der.sequence(der.integer(5), der.oid("2.5.4.3"))
    items = der.children(der.read(encoded).content)
    assert items[0].tag == der.INTEGER
    assert items[1].tag == der.OID
    assert items[1].encoded == der.oid("2.5.4.3")


def test_hand_signature_matches_the_standard(key):
    """Our signature equals and verifies like the library's PKCS#1."""
    signature = pkcs1.sign(key, b"contract")
    standard = pkcs1_15.new(key).sign(SHA256.new(b"contract"))
    assert signature == standard
    pkcs1.verify(key.public_key(), b"contract", signature)


def test_altered_message_or_signature_fails(key):
    """One changed byte in the message or signature is detected."""
    signature = pkcs1.sign(key, b"contract")
    with pytest.raises(pkcs1.SignatureError):
        pkcs1.verify(key.public_key(), b"contracT", signature)
    damaged = bytes([signature[0] ^ 1]) + signature[1:]
    with pytest.raises(pkcs1.SignatureError):
        pkcs1.verify(key.public_key(), b"contract", damaged)


def test_another_key_fails(key):
    """A signature does not verify under another public key."""
    signature = pkcs1.sign(key, b"contract")
    with pytest.raises(pkcs1.SignatureError):
        pkcs1.verify(RSA.generate(1024).public_key(), b"contract",
                     signature)
