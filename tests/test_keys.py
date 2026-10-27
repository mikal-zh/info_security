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
    enc_key_sizes = []
    prefixes = set()
    for cipher in CIPHERS:
        pair = vault.cipher_keys(cipher)
        enc_key_sizes.append(len(pair.enc_key))
        prefixes.add(pair.enc_key[:8])
        prefixes.add(pair.mac_key[:8])
    assert len(prefixes) == 2 * len(CIPHERS)
    assert enc_key_sizes == [32, 8, 16]


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
