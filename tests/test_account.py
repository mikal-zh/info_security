# PROJECT, 2026
# info_security
# File description:
# Account tests: password change and erasure.

"""Account tests: password change and erasure."""

from tests.helpers import (NIK, PASSWORD, blob_suffixes, post_form,
                           table_counts, upload)

NEW_PASSWORD = "new-password-123"


def test_password_change_keeps_documents_readable(client):
    """After a password change, documents open with the new password."""
    upload(client, b"payslip", "payslip.pdf", "office")
    post_form(client, "/account/password", {"old": PASSWORD,
                                            "new": NEW_PASSWORD,
                                            "confirm": NEW_PASSWORD})
    post_form(client, "/logout", {})
    post_form(client, "/login", {"username": "emp-001",
                                 "password": NEW_PASSWORD})
    assert client.get("/documents/1/download?cipher=RC4").data == b"payslip"


def test_erasure_removes_everything(app, client):
    """Erasure leaves no row and no encrypted file behind."""
    upload(client, b"cv", "cv.pdf", "office")
    post_form(client, "/personal-data", {"nik": NIK})
    post_form(client, "/account/erase", {"password": PASSWORD})
    assert table_counts(app) == [0, 0, 0]
    assert blob_suffixes(app) == []
