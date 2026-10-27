# PROJECT, 2026
# info_security
# File description:
# Document tests: exact retrieval, no leaks, tampering and access control.

"""Document tests: exact retrieval, no leaks, tampering, access control."""

import os

import pytest

from tests.helpers import post_form, register_and_login, stored_bytes, upload


@pytest.mark.parametrize("cipher", ["AES", "DES", "RC4"])
def test_document_comes_back_bit_exact_from_every_copy(client, cipher):
    """Each copy decrypts to exactly the uploaded bytes and name."""
    data = os.urandom(300_000)
    upload(client, data, "contract.docx", "office")
    resp = client.get(f"/documents/1/download?cipher={cipher}")
    assert resp.status_code == 200 and resp.data == data
    assert "contract.docx" in resp.headers["Content-Disposition"]


def test_three_copies_on_disk_and_filename_not_leaked(app, client):
    """Three files with random names; neither content nor name in clear."""
    upload(client, b"KTP scan bytes " * 1000, "ktp_aditya_pratama.png")
    suffixes = sorted(path.suffix for path in app.config["BLOB_DIR"].iterdir())
    assert suffixes == [".aes", ".des", ".rc4"]
    assert b"aditya" not in stored_bytes(app)
    assert b"KTP scan" not in stored_bytes(app)


def test_tampered_copy_is_not_released(app, client):
    """A modified DES copy is refused while the AES copy still works."""
    upload(client, b"interview video" * 5000, "interview.mp4", "video")
    blob = next(path for path in app.config["BLOB_DIR"].iterdir()
                if path.suffix == ".des")
    raw = bytearray(blob.read_bytes())
    raw[100] ^= 0xFF
    blob.write_bytes(bytes(raw))
    resp = client.get("/documents/1/download?cipher=DES",
                      follow_redirects=True)
    assert b"has been altered since you uploaded it" in resp.data
    assert client.get("/documents/1/download?cipher=AES").status_code == 200
    resp = post_form(client, "/documents/1/verify", {}, follow=True)
    assert b"DES copy is damaged" in resp.data
    assert b"AES copy is intact" in resp.data


def test_other_employee_cannot_get_document(app, client):
    """Another employee gets a 404 for someone else's document."""
    upload(client, b"private", "ktp.png")
    other = app.test_client()
    register_and_login(other, "emp-002")
    assert other.get("/documents/1/download?cipher=AES").status_code == 404
    assert post_form(other, "/documents/1/delete", {}).status_code == 404


def test_wrong_extension_is_rejected(app, client):
    """A file type that does not match its category is not stored."""
    resp = upload(client, b"x", "virus.exe", "office")
    assert resp.status_code == 302
    assert list(app.config["BLOB_DIR"].iterdir()) == []
