# PROJECT, 2026
# info_security
# File description:
# Key import tests: own PEM key accepted, unusable key files refused.

"""Key import tests: own PEM key accepted, unusable key files refused."""

import io
import sqlite3

import pytest
from Crypto.PublicKey import RSA

from tests.helpers import csrf

OWN_KEY = RSA.generate(2048)


def _import(client, data: bytes, passphrase: str = ""):
    """Submit a key file on the Keys page."""
    form = {"csrf_token": csrf(client), "passphrase": passphrase,
            "key_file": (io.BytesIO(data), "key.pem")}
    return client.post("/keys/import", data=form, follow_redirects=True,
                       content_type="multipart/form-data")


def _stored_public_key(app) -> bytes:
    """The public key stored for the first user."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    return conn.execute("SELECT public_key FROM user_keys").fetchone()[0]


def test_own_key_is_imported(app, client):
    """A passphrase-protected PEM key becomes the user's key pair."""
    pem = OWN_KEY.export_key(passphrase="secret phrase", pkcs=8,
                             protection="scryptAndAES128-CBC")
    resp = _import(client, pem, "secret phrase")
    assert b"Your key is imported" in resp.data
    public = OWN_KEY.public_key().export_key(format="DER")
    assert _stored_public_key(app) == public
    assert b"imported on" in client.get("/keys").data


@pytest.mark.parametrize("data, message", [
    (OWN_KEY.public_key().export_key(), b"That&#39;s a public key"),
    (RSA.generate(1024).export_key(), b"too short"),
    (b"-----BEGIN RSA PRIVATE KEY-----\ngarbage", b"couldn&#39;t read"),
])
def test_unusable_key_files_are_refused(app, client, data, message):
    """Public, short and unreadable keys are refused and not stored."""
    assert message in _import(client, data).data
    conn = sqlite3.connect(app.config["DB_PATH"])
    assert conn.execute("SELECT COUNT(*) FROM user_keys").fetchone()[0] == 0


def test_wrong_passphrase_is_refused(client):
    """An encrypted key with the wrong passphrase is not imported."""
    pem = OWN_KEY.export_key(passphrase="right one", pkcs=8,
                             protection="scryptAndAES128-CBC")
    assert b"couldn&#39;t read" in _import(client, pem, "wrong one").data


def test_import_does_not_replace_a_key(client):
    """A user who already has a key pair cannot overwrite it."""
    _import(client, OWN_KEY.export_key())
    resp = _import(client, RSA.generate(2048).export_key())
    assert b"You already have a key pair" in resp.data
