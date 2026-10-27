# PROJECT, 2026
# info_security
# File description:
# Round-trip and randomisation tests for the three ciphers.

"""Round-trip and randomisation tests for AES, DES and RC4."""

import os

import pytest

from hrvault.crypto import CIPHERS, VaultKeys, ciphers, envelope

SIZES = [0, 1, 7, 8, 15, 16, 17, 1000, 65537]
RC4_BODY = slice(2 + 16, -32)


@pytest.fixture
def vault():
    """Fresh random vault keys for each test."""
    return VaultKeys.generate()


@pytest.mark.parametrize("cipher", CIPHERS)
@pytest.mark.parametrize("size", SIZES)
def test_roundtrip_is_exact(vault, cipher, size):
    """Any length decrypts to the exact input, with the expected overhead."""
    data = os.urandom(size)
    sealed = vault.seal(cipher, data, "ctx")
    assert vault.open(cipher, sealed, "ctx") == data
    assert len(sealed) == size + envelope.overhead(cipher, size)


@pytest.mark.parametrize("cipher", CIPHERS)
def test_same_plaintext_gives_different_ciphertext(vault, cipher):
    """Random IV or per-message key: equal inputs never look equal."""
    first = vault.seal(cipher, b"3578012304950001", "ctx")
    second = vault.seal(cipher, b"3578012304950001", "ctx")
    assert first != second


def test_rc4_messages_never_share_keystream(vault):
    """XOR of two RC4 ciphertexts must not reveal XOR of the plaintexts."""
    plain1, plain2 = os.urandom(256), os.urandom(256)
    body1 = vault.seal("RC4", plain1, "ctx")[RC4_BODY]
    body2 = vault.seal("RC4", plain2, "ctx")[RC4_BODY]
    xor_cipher = bytes(a ^ b for a, b in zip(body1, body2))
    xor_plain = bytes(a ^ b for a, b in zip(plain1, plain2))
    assert xor_cipher != xor_plain


def test_cbc_ciphers_use_block_sized_iv():
    """AES uses a 16-byte IV, DES an 8-byte IV, RC4 a 16-byte nonce."""
    assert ciphers.NONCE_SIZES == {"AES": 16, "DES": 8, "RC4": 16}


def test_unknown_cipher_is_refused():
    """Only AES, DES and RC4 are accepted."""
    with pytest.raises(ValueError):
        ciphers.encrypt("ECB", b"0" * 16, b"data")
