# PROJECT, 2026
# info_security
# File description:
# Key pair tests: created at first login, private half sealed at rest.

"""Key pair tests: created at first login, private half sealed at rest."""

import sqlite3

import pytest
from Crypto.PublicKey import RSA

from tests.helpers import post_form


def _key_row(app):
    """(public_key, private_key) stored for the first user."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    return conn.execute(
        "SELECT public_key, private_key FROM user_keys").fetchone()


def test_key_pair_is_created_on_first_login(app, client):
    """Logging in for the first time stores exactly one key pair."""
    public, sealed = _key_row(app)
    assert RSA.import_key(public).size_in_bits() == 1024
    assert not RSA.import_key(public).has_private()
    page = client.get("/account").get_data(as_text=True)
    assert "Your RSA key pair" in page


def test_private_key_is_not_stored_in_clear(app, client):
    """The stored private key is an envelope, not a loadable key."""
    sealed = _key_row(app)[1]
    assert sealed[:2] == bytes([1, 1])
    with pytest.raises(ValueError):
        RSA.import_key(sealed)


def test_second_login_keeps_the_same_key(app, client):
    """A key pair is generated once, not at every login."""
    first = _key_row(app)[0]
    post_form(client, "/logout", {})
    post_form(client, "/login", {"username": "emp-001",
                                 "password": "onboarding-2026"})
    assert _key_row(app)[0] == first
