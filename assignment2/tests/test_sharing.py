# PROJECT, 2026
# info_security
# File description:
# Sharing tests: request, approve, read, reject, revoke and isolation.

"""Sharing tests: request, approve, read, reject, revoke, isolation."""

import os
import sqlite3

import pytest

from tests.helpers import NIK, post_form, register_and_login, upload

CONTRACT = os.urandom(50_000)


@pytest.fixture
def hr(app, client):
    """emp-001 has a file; hr-001 has asked for it."""
    post_form(client, "/personal-data", {"full_name": "Aditya", "nik": NIK})
    upload(client, CONTRACT, "contract.pdf", "office")
    hr_client = app.test_client()
    register_and_login(hr_client, "hr-001")
    post_form(hr_client, "/sharing/request", {"username": "emp-001"})
    return hr_client


def _share_files(app) -> list:
    """Encrypted files currently stored for shares."""
    files = []
    for path in app.config["SHARE_DIR"].iterdir():
        files.append(path)
    return files


def test_approved_share_is_readable_by_the_requester(client, hr):
    """After approval the requester sees the data and gets exact bytes."""
    assert b"hr-001" in client.get("/sharing").data
    post_form(client, "/sharing/1/approve", {})
    page = hr.get("/shared/1").get_data(as_text=True)
    assert NIK in page and "contract.pdf" in page
    resp = hr.get("/shared/1/documents/1")
    assert resp.status_code == 200 and resp.data == CONTRACT


def test_pending_or_rejected_request_gives_nothing(client, hr):
    """No access before approval, nor after a rejection."""
    assert hr.get("/shared/1").status_code == 404
    post_form(client, "/sharing/1/reject", {})
    assert hr.get("/shared/1").status_code == 404
    assert post_form(client, "/sharing/1/approve", {}).status_code == 404


def test_revoke_deletes_the_shared_copy(app, client, hr):
    """Revoking removes the files and the requester loses access."""
    post_form(client, "/sharing/1/approve", {})
    assert len(_share_files(app)) == 1
    post_form(client, "/sharing/1/revoke", {})
    assert _share_files(app) == []
    assert hr.get("/shared/1").status_code == 404


def test_third_user_and_requester_cannot_decide(app, client, hr):
    """Only the owner approves; only the requester reads."""
    assert post_form(hr, "/sharing/1/approve", {}).status_code == 404
    post_form(client, "/sharing/1/approve", {})
    other = app.test_client()
    register_and_login(other, "emp-003")
    assert other.get("/shared/1").status_code == 404
    assert client.get("/shared/1").status_code == 404


def test_share_at_rest_is_encrypted_and_key_wrapped(app, client, hr):
    """Shared copy holds no plaintext; the stored key is RSA-wrapped."""
    post_form(client, "/sharing/1/approve", {})
    stored = _share_files(app)[0].read_bytes()
    assert CONTRACT[:64] not in stored
    conn = sqlite3.connect(app.config["DB_PATH"])
    wrapped = conn.execute("SELECT wrapped_key FROM access_requests")
    assert len(wrapped.fetchone()[0]) == 1024 // 8
    sealed = conn.execute("SELECT sealed FROM shared_fields").fetchall()
    for row in sealed:
        assert NIK.encode() not in row[0]


def test_tampered_shared_copy_is_refused(app, client, hr):
    """A modified shared file is not handed to the requester."""
    post_form(client, "/sharing/1/approve", {})
    path = _share_files(app)[0]
    raw = bytearray(path.read_bytes())
    raw[50] ^= 0xFF
    path.write_bytes(bytes(raw))
    resp = hr.get("/shared/1/documents/1", follow_redirects=True)
    assert b"has been altered" in resp.data


def test_erasing_the_owner_removes_shares(app, client, hr):
    """Account erasure also deletes the copies shared with others."""
    post_form(client, "/sharing/1/approve", {})
    post_form(client, "/account/erase", {"password": "onboarding-2026"})
    assert _share_files(app) == []
    assert hr.get("/shared/1").status_code == 404
