# PROJECT, 2026
# info_security
# File description:
# Web signing tests: sign stored PDFs, check them, verify any upload.

"""Web signing tests: sign stored PDFs, check them, verify any upload."""

import io

from hrvault.pdfsign import verifier
from tests.helpers import csrf, post_form, register_and_login, upload
from tests.sample_pdfs import classic_pdf


def _check_upload(client, data: bytes):
    """Submit a PDF to the "Verify PDF" page."""
    form = {"csrf_token": csrf(client),
            "file": (io.BytesIO(data), "received.pdf")}
    return client.post("/signatures/verify", data=form,
                       content_type="multipart/form-data")


def test_signing_embeds_a_valid_signature(client):
    """The stored PDF now carries emp-001's valid signature."""
    upload(client, classic_pdf(), "contract.pdf", "office")
    resp = post_form(client, "/documents/1/sign", {}, follow=True)
    assert b"we generated one first" in resp.data
    assert b"signed" in client.get("/documents").data
    signed = client.get("/documents/1/download?cipher=AES").data
    checks = verifier.verify_pdf(signed)
    assert len(checks) == 1 and checks[0].valid
    assert checks[0].signer == "emp-001"


def test_all_three_copies_hold_the_signed_pdf(client):
    """AES, DES and RC4 copies are rewritten with the same bytes."""
    upload(client, classic_pdf(), "contract.pdf", "office")
    post_form(client, "/documents/1/sign", {})
    copies = set()
    for cipher in ("AES", "DES", "RC4"):
        copies.add(client.get(f"/documents/1/download?cipher={cipher}").data)
    assert len(copies) == 1
    assert copies.pop().startswith(classic_pdf())


def test_report_names_the_registered_signer(client):
    """The document report links the key to emp-001."""
    upload(client, classic_pdf(), "contract.pdf", "office")
    post_form(client, "/documents/1/sign", {})
    page = client.get("/documents/1/signatures").get_data(as_text=True)
    assert "This key belongs to emp-001 in this vault." in page
    assert "The signed content has not changed." in page


def test_only_pdfs_and_only_the_owner(app, client):
    """A Word file cannot be signed; another user gets a 404."""
    upload(client, b"PK fake docx", "cv.docx", "office")
    resp = post_form(client, "/documents/1/sign", {}, follow=True)
    assert b"Only PDF documents can be signed" in resp.data
    other = app.test_client()
    register_and_login(other, "emp-002")
    assert post_form(other, "/documents/1/sign", {}).status_code == 404
    assert other.get("/documents/1/signatures").status_code == 404


def test_any_user_can_verify_a_received_pdf(app, client):
    """emp-002 checks a PDF signed by emp-001 and sees who signed it."""
    upload(client, classic_pdf(), "contract.pdf", "office")
    post_form(client, "/documents/1/sign", {})
    signed = client.get("/documents/1/download?cipher=AES").data
    other = app.test_client()
    register_and_login(other, "emp-002")
    page = _check_upload(other, signed).get_data(as_text=True)
    assert "This key belongs to emp-001 in this vault." in page
    tampered = signed.replace(b"Employment", b"Unemployed")
    page = _check_upload(other, tampered).get_data(as_text=True)
    assert "The signed content was changed after signing." in page


def test_unsigned_and_invalid_uploads(client):
    """No signature and non-PDF files get a clear message."""
    page = _check_upload(client, classic_pdf()).get_data(as_text=True)
    assert "This PDF carries no signature." in page
    resp = client.post("/signatures/verify", follow_redirects=True,
                       data={"csrf_token": csrf(client),
                             "file": (io.BytesIO(b"hello"), "x.pdf")},
                       content_type="multipart/form-data")
    assert b"couldn&#39;t read that PDF" in resp.data
