# PROJECT, 2026
# info_security
# File description:
# Key hierarchy tests: subkey independence and vault-key wrapping.

"""Tests for subkey derivation and password-based key wrapping."""

import os

import pytest

from hrvault.crypto import CIPHERS, IntegrityError, VaultKeys, keys


def test_subkeys_are_independent():
    """Every encryption and MAC key differs, with the right key sizes."""
    vault = VaultKeys.generate()
    pairs = [vault.cipher_keys(cipher) for cipher in CIPHERS]
    enc_keys = [pair.enc_key for pair in pairs]
    derived = enc_keys + [pair.mac_key for pair in pairs]
    assert len({key[:8] for key in derived}) == len(derived)
    assert [len(key) for key in enc_keys] == [32, 8, 16]


def test_vault_key_unwraps_with_right_password():
    """The KEK from the right password recovers the vault key."""
    salt = keys.new_salt()
    _, kek = keys.derive_login_secrets("correct horse", salt, 1000)
    vault_key = os.urandom(32)
    wrapped = keys.wrap_vault_key(kek, vault_key, "emp-001")
    assert keys.unwrap_vault_key(kek, wrapped, "emp-001") == vault_key


def test_vault_key_refuses_wrong_password_or_user():
    """A wrong password or another username cannot unwrap the key."""
    salt = keys.new_salt()
    _, kek = keys.derive_login_secrets("correct horse", salt, 1000)
    _, bad_kek = keys.derive_login_secrets("wrong horse", salt, 1000)
    wrapped = keys.wrap_vault_key(kek, os.urandom(32), "emp-001")
    with pytest.raises(IntegrityError):
        keys.unwrap_vault_key(bad_kek, wrapped, "emp-001")
    with pytest.raises(IntegrityError):
        keys.unwrap_vault_key(kek, wrapped, "emp-002")
