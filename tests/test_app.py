import io
import os
import re
import sqlite3

import pytest

from hrvault import create_app

PASSWORD = "onboarding-2026"
NIK = "3578012304950001"


@pytest.fixture
def app(tmp_path):
    return create_app({"DATA_DIR": tmp_path, "PBKDF2_ITERATIONS": 1000, "TESTING": True})


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def register_and_login(client, username="emp-001", password=PASSWORD):
    token = csrf(client, "/register")
    client.post("/register", data={"username": username, "password": password,
                                   "confirm": password, "csrf_token": token})
    token = csrf(client)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


def upload(client, data, filename="ktp.png", category="id_scan"):
    token = csrf(client, "/documents")
    return client.post("/documents", data={"category": category, "csrf_token": token,
                                           "file": (io.BytesIO(data), filename)},
                       content_type="multipart/form-data")


def all_stored_bytes(app):
    db = sqlite3.connect(app.config["DB_PATH"]).execute(
        "SELECT * FROM personal_data UNION ALL SELECT meta_aes, meta_des, meta_rc4, 0, 0, 0 FROM documents"
    ).fetchall()
    blobs = [p.read_bytes() for p in app.config["BLOB_DIR"].iterdir()]
    return b"".join(v if isinstance(v, bytes) else str(v).encode() for row in db for v in row) + b"".join(blobs)


def test_pages_require_login(app):
    client = app.test_client()
    for path in ["/dashboard", "/personal-data", "/documents", "/documents/1/download", "/account"]:
        assert client.get(path).status_code == 302


def test_post_without_csrf_token_is_rejected(app):
    client = app.test_client()
    assert client.post("/login", data={"username": "x", "password": "y"}).status_code == 400


def test_wrong_password_is_refused(app):
    client = app.test_client()
    register_and_login(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/account")})
    resp = client.post("/login", data={"username": "emp-001", "password": "wrong-password",
                                       "csrf_token": csrf(client)}, follow_redirects=True)
    assert b"employee number and password don&#39;t match" in resp.data


def test_personal_data_roundtrip_and_nothing_in_clear(app):
    client = app.test_client()
    register_and_login(client)
    client.post("/personal-data", data={"nik": NIK, "religion": "Islam", "csrf_token": csrf(client, "/personal-data")})
    page = client.get("/personal-data").get_data(as_text=True)
    assert f'value="{NIK}"' in page
    assert page.count("fa-circle-check") >= 6  # three verified copies for each of the two fields

    stored = all_stored_bytes(app)
    assert NIK.encode() not in stored and b"Islam" not in stored
    rows = sqlite3.connect(app.config["DB_PATH"]).execute("SELECT aes, des, rc4 FROM personal_data").fetchall()
    assert len(rows) == 2 and all(len(set(r)) == 3 for r in rows)


@pytest.mark.parametrize("cipher", ["AES", "DES", "RC4"])
def test_document_comes_back_bit_exact_from_every_copy(app, cipher):
    client = app.test_client()
    register_and_login(client)
    data = os.urandom(300_000)
    upload(client, data, "contract.docx", "office")
    resp = client.get(f"/documents/1/download?cipher={cipher}")
    assert resp.status_code == 200
    assert resp.data == data
    assert "contract.docx" in resp.headers["Content-Disposition"]


def test_three_copies_on_disk_and_filename_not_leaked(app):
    client = app.test_client()
    register_and_login(client)
    upload(client, b"KTP scan bytes " * 1000, "ktp_aditya_pratama.png")
    files = sorted(p.suffix for p in app.config["BLOB_DIR"].iterdir())
    assert files == [".aes", ".des", ".rc4"]
    assert b"aditya" not in all_stored_bytes(app) and b"KTP scan" not in all_stored_bytes(app)


def test_tampered_copy_is_not_released(app):
    client = app.test_client()
    register_and_login(client)
    upload(client, b"interview video" * 5000, "interview.mp4", "video")
    blob = next(p for p in app.config["BLOB_DIR"].iterdir() if p.suffix == ".des")
    raw = bytearray(blob.read_bytes())
    raw[100] ^= 0xFF
    blob.write_bytes(bytes(raw))

    resp = client.get("/documents/1/download?cipher=DES", follow_redirects=True)
    assert b"has been altered since you uploaded it" in resp.data
    assert client.get("/documents/1/download?cipher=AES").status_code == 200

    resp = client.post("/documents/1/verify", data={"csrf_token": csrf(client, "/documents")}, follow_redirects=True)
    assert b"DES copy is damaged" in resp.data and b"AES copy is intact" in resp.data


def test_other_employee_cannot_get_document(app):
    alice, bob = app.test_client(), app.test_client()
    register_and_login(alice, "emp-001")
    upload(alice, b"private", "ktp.png")
    register_and_login(bob, "emp-002")
    assert bob.get("/documents/1/download?cipher=AES").status_code == 404
    assert bob.post("/documents/1/delete", data={"csrf_token": csrf(bob, "/documents")}).status_code == 404


def test_wrong_extension_is_rejected(app):
    client = app.test_client()
    register_and_login(client)
    resp = upload(client, b"x", "virus.exe", "office")
    assert len(list(app.config["BLOB_DIR"].iterdir())) == 0
    assert resp.status_code == 302


def test_cookie_carries_no_password_or_key(app):
    client = app.test_client()
    resp = register_and_login(client)
    cookie = resp.headers.get("Set-Cookie", "")
    assert PASSWORD not in cookie
    from flask.sessions import SecureCookieSessionInterface
    serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    session = serializer.loads(client.get_cookie("session").value)
    assert set(session) <= {"token", "username", "csrf", "_flashes"}


def test_logout_drops_keys(app):
    client = app.test_client()
    register_and_login(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/account")})
    assert client.get("/documents").status_code == 302


def test_password_change_keeps_documents_readable(app):
    client = app.test_client()
    register_and_login(client)
    upload(client, b"payslip", "payslip.pdf", "office")
    client.post("/account/password", data={"old": PASSWORD, "new": "new-password-123", "confirm": "new-password-123",
                                           "csrf_token": csrf(client, "/account")})
    client.post("/logout", data={"csrf_token": csrf(client, "/account")})
    client.post("/login", data={"username": "emp-001", "password": "new-password-123", "csrf_token": csrf(client)})
    assert client.get("/documents/1/download?cipher=RC4").data == b"payslip"


def test_erasure_removes_everything(app):
    client = app.test_client()
    register_and_login(client)
    upload(client, b"cv", "cv.pdf", "office")
    client.post("/personal-data", data={"nik": NIK, "csrf_token": csrf(client, "/personal-data")})
    client.post("/account/erase", data={"password": PASSWORD, "csrf_token": csrf(client, "/account")})
    conn = sqlite3.connect(app.config["DB_PATH"])
    assert [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users", "personal_data", "documents")] == [0, 0, 0]
    assert list(app.config["BLOB_DIR"].iterdir()) == []
