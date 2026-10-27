import os

import pytest

from hrvault.crypto import CIPHERS, IntegrityError, VaultKeys, ciphers, envelope, keys

SIZES = [0, 1, 7, 8, 15, 16, 17, 1000, 65537]


@pytest.fixture
def vk():
    return VaultKeys.generate()


@pytest.mark.parametrize("cipher", CIPHERS)
@pytest.mark.parametrize("size", SIZES)
def test_roundtrip_is_exact(vk, cipher, size):
    data = os.urandom(size)
    sealed = vk.seal(cipher, data, "ctx")
    assert vk.open(cipher, sealed, "ctx") == data
    assert len(sealed) == size + envelope.overhead(cipher, size)


@pytest.mark.parametrize("cipher", CIPHERS)
def test_same_plaintext_gives_different_ciphertext(vk, cipher):
    # Random IV (CBC) / per-message key (RC4): no equality leak, no keystream reuse.
    a = vk.seal(cipher, b"3578012304950001", "ctx")
    b = vk.seal(cipher, b"3578012304950001", "ctx")
    assert a != b


def test_rc4_messages_never_share_keystream(vk):
    p1, p2 = os.urandom(256), os.urandom(256)
    c1 = vk.seal("RC4", p1, "ctx")[2 + 16 : -32]
    c2 = vk.seal("RC4", p2, "ctx")[2 + 16 : -32]
    xor_ct = bytes(x ^ y for x, y in zip(c1, c2))
    xor_pt = bytes(x ^ y for x, y in zip(p1, p2))
    assert xor_ct != xor_pt


@pytest.mark.parametrize("cipher", CIPHERS)
@pytest.mark.parametrize("position", [0, 1, 5, -40, -1])
def test_any_flipped_bit_is_rejected(vk, cipher, position):
    sealed = bytearray(vk.seal(cipher, b"Bank Mandiri 141-00-1234567-8", "ctx"))
    sealed[position] ^= 0x01
    with pytest.raises(IntegrityError):
        vk.open(cipher, bytes(sealed), "ctx")


@pytest.mark.parametrize("cipher", CIPHERS)
def test_ciphertext_moved_to_other_context_is_rejected(vk, cipher):
    sealed = vk.seal(cipher, b"O+", "user:1|field:blood_type")
    with pytest.raises(IntegrityError):
        vk.open(cipher, sealed, "user:2|field:blood_type")


@pytest.mark.parametrize("cipher", CIPHERS)
def test_other_users_key_is_rejected(vk, cipher):
    sealed = vk.seal(cipher, b"secret", "ctx")
    with pytest.raises(IntegrityError):
        VaultKeys.generate().open(cipher, sealed, "ctx")


def test_truncated_envelope_is_rejected(vk):
    with pytest.raises(IntegrityError):
        vk.open("AES", b"\x01\x01short", "ctx")


def test_subkeys_are_independent(vk):
    derived = [vk.enc_key(c) for c in CIPHERS] + [vk.mac_key(c) for c in CIPHERS]
    assert len({k[:8] for k in derived}) == len(derived)
    assert [len(vk.enc_key(c)) for c in CIPHERS] == [32, 8, 16]


def test_vault_key_wrap_requires_right_password_and_user():
    salt = keys.new_salt()
    _, kek = keys.derive_login_secrets("correct horse", salt, 1000)
    _, bad_kek = keys.derive_login_secrets("wrong horse", salt, 1000)
    vault_key = os.urandom(32)
    wrapped = keys.wrap_vault_key(kek, vault_key, "emp-001")
    assert keys.unwrap_vault_key(kek, wrapped, "emp-001") == vault_key
    with pytest.raises(IntegrityError):
        keys.unwrap_vault_key(bad_kek, wrapped, "emp-001")
    with pytest.raises(IntegrityError):
        keys.unwrap_vault_key(kek, wrapped, "emp-002")


def test_cbc_ciphers_use_block_sized_iv():
    assert ciphers.NONCE_SIZES == {"AES": 16, "DES": 8, "RC4": 16}
