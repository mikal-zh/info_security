# PROJECT, 2026
# info_security
# File description:
# Key pair tests: generate on request, sealed at rest, certificate.

"""Key pair tests: generate on request, sealed at rest, certificate."""

import sqlite3

import pytest
from Crypto.PublicKey import RSA

from hrvault.pdfsign import certificate_info
from tests.helpers import post_form


def _key_row(app):
    """The stored key row of the first user, or None."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn.execute("SELECT * FROM user_keys").fetchone()


def test_no_key_until_the_user_asks(app, client):
    """Logging in does not create keys; the Keys page offers both ways."""
    assert _key_row(app) is None
    page = client.get("/keys").get_data(as_text=True)
    assert "Generate a key pair" in page and "Import your own key" in page


def test_generate_creates_one_sealed_key_pair(app, client):
    """Generating stores a public key and a sealed private key, once."""
    post_form(client, "/keys/generate", {})
    row = _key_row(app)
    assert not RSA.import_key(row["public_key"]).has_private()
    assert row["private_key"][:2] == bytes([1, 1])
    with pytest.raises(ValueError):
        RSA.import_key(row["private_key"])
    resp = post_form(client, "/keys/generate", {}, follow=True)
    assert b"You already have a key pair" in resp.data


def test_certificate_names_the_user(app, client):
    """The downloadable certificate is for emp-001 and this public key."""
    post_form(client, "/keys/generate", {})
    resp = client.get("/keys/certificate.cer")
    cert = certificate_info.parse(resp.data)
    assert cert.subject == "emp-001"
    assert cert.public_key == _key_row(app)["public_key"]
    assert certificate_info.is_self_signed_by_its_key(cert)
    assert b"BEGIN PUBLIC KEY" in client.get("/keys/public.pem").data


def test_downloads_need_a_key_pair(client):
    """Without a key pair there is nothing to download."""
    assert client.get("/keys/certificate.cer").status_code == 404
    assert client.get("/keys/public.pem").status_code == 404
