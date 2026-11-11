# PROJECT, 2026
# info_security
# File description:
# Integrity tests: tampering, relocation and wrong keys are rejected.

"""Integrity tests for the encrypt-then-MAC envelope."""

import pytest

from hrvault.crypto import CIPHERS, IntegrityError, VaultKeys


@pytest.fixture
def vault():
    """Fresh random vault keys for each test."""
    return VaultKeys.generate()


@pytest.mark.parametrize("cipher", CIPHERS)
@pytest.mark.parametrize("position", [0, 1, 5, -40, -1])
def test_any_flipped_bit_is_rejected(vault, cipher, position):
    """One flipped bit in header, IV, ciphertext or tag is detected."""
    sealed = bytearray(vault.seal(cipher, b"Bank Mandiri 141-00-12", "ctx"))
    sealed[position] ^= 0x01
    with pytest.raises(IntegrityError):
        vault.open(cipher, bytes(sealed), "ctx")


@pytest.mark.parametrize("cipher", CIPHERS)
def test_ciphertext_moved_to_other_context_is_rejected(vault, cipher):
    """A value copied into another user's row does not decrypt."""
    sealed = vault.seal(cipher, b"O+", "user:1|field:blood_type")
    with pytest.raises(IntegrityError):
        vault.open(cipher, sealed, "user:2|field:blood_type")


@pytest.mark.parametrize("cipher", CIPHERS)
def test_other_users_key_is_rejected(vault, cipher):
    """Another user's keys cannot open the envelope."""
    sealed = vault.seal(cipher, b"secret", "ctx")
    with pytest.raises(IntegrityError):
        VaultKeys.generate().open(cipher, sealed, "ctx")


def test_truncated_envelope_is_rejected(vault):
    """An envelope too short to hold IV and tag is refused."""
    with pytest.raises(IntegrityError):
        vault.open("AES", b"\x01\x01short", "ctx")
