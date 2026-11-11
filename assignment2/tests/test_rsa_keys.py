# PROJECT, 2026
# info_security
# File description:
# RSA tests: sealed private key, OAEP round trip and wrong-key refusal.

"""RSA tests: sealed private key, OAEP round trip, wrong-key refusal."""

import pytest

from hrvault.crypto import IntegrityError, VaultKeys
from hrvault.crypto import rsa_keys

BITS = 1024


@pytest.fixture(scope="module")
def key_pair():
    """One RSA key pair shared by the tests of this module."""
    return rsa_keys.generate(BITS)


def test_private_key_round_trip_through_the_vault(key_pair):
    """A sealed private key opens to the same key with the right keys."""
    keys = VaultKeys.generate()
    sealed = rsa_keys.seal_private(keys, key_pair, "user:1|rsa")
    assert key_pair.export_key(format="DER") not in sealed
    assert rsa_keys.open_private(keys, sealed, "user:1|rsa") == key_pair


def test_sealed_private_key_needs_its_owner_and_context(key_pair):
    """Another user's keys or another context cannot open it."""
    keys = VaultKeys.generate()
    sealed = rsa_keys.seal_private(keys, key_pair, "user:1|rsa")
    with pytest.raises(IntegrityError):
        rsa_keys.open_private(VaultKeys.generate(), sealed, "user:1|rsa")
    with pytest.raises(IntegrityError):
        rsa_keys.open_private(keys, sealed, "user:2|rsa")


def test_oaep_round_trip_and_randomised(key_pair):
    """OAEP decrypts back and two encryptions of a key differ."""
    public = rsa_keys.public_der(key_pair)
    first = rsa_keys.encrypt_for(public, b"k" * 32)
    second = rsa_keys.encrypt_for(public, b"k" * 32)
    assert first != second
    assert rsa_keys.decrypt_with(key_pair, first) == b"k" * 32


def test_oaep_refuses_the_wrong_private_key(key_pair):
    """A ciphertext for one key does not open with another key."""
    ciphertext = rsa_keys.encrypt_for(rsa_keys.public_der(key_pair), b"x")
    with pytest.raises(IntegrityError):
        rsa_keys.decrypt_with(rsa_keys.generate(BITS), ciphertext)


def test_fingerprint_and_size(key_pair):
    """The fingerprint has 8 groups and the size is the modulus size."""
    public = rsa_keys.public_der(key_pair)
    assert len(rsa_keys.fingerprint(public).split(":")) == 8
    assert rsa_keys.key_bits(public) == BITS
