# PROJECT, 2026
# info_security
# File description:
# Helpers driving the web app through Flask's test client.

"""Helpers driving the web app through Flask's test client."""

import io
import re
import sqlite3

PASSWORD = "onboarding-2026"
NIK = "3578012304950001"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def csrf(client) -> str:
    """The CSRF token of the client's current session."""
    html = client.get("/login").get_data(as_text=True)
    return CSRF_RE.search(html).group(1)


def post_form(client, path: str, data: dict, follow: bool = False):
    """POST a form with a valid CSRF token added."""
    data = {**data, "csrf_token": csrf(client)}
    return client.post(path, data=data, follow_redirects=follow)


def register_and_login(client, username: str = "emp-001"):
    """Create an account with PASSWORD and log the client in."""
    post_form(client, "/register", {"username": username,
                                    "password": PASSWORD,
                                    "confirm": PASSWORD})
    return post_form(client, "/login", {"username": username,
                                        "password": PASSWORD})


def upload(client, data: bytes, filename: str, category: str = "id_scan"):
    """Upload `data` as `filename` through the documents form."""
    form = {"category": category, "csrf_token": csrf(client),
            "file": (io.BytesIO(data), filename)}
    return client.post("/documents", data=form,
                       content_type="multipart/form-data")


def stored_bytes(app) -> bytes:
    """Every byte at rest: database rows and encrypted files on disk."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    rows = conn.execute(
        "SELECT aes, des, rc4 FROM personal_data UNION ALL "
        "SELECT meta_aes, meta_des, meta_rc4 FROM documents").fetchall()
    stored = b""
    for row in rows:
        for value in row:
            stored += value
    for path in app.config["BLOB_DIR"].iterdir():
        stored += path.read_bytes()
    return stored


def table_counts(app) -> list[int]:
    """Number of rows in the users, personal_data and documents tables."""
    conn = sqlite3.connect(app.config["DB_PATH"])
    counts = []
    for name in ("users", "personal_data", "documents"):
        query = f"SELECT COUNT(*) FROM {name}"
        counts.append(conn.execute(query).fetchone()[0])
    return counts


def blob_suffixes(app) -> list[str]:
    """Sorted extensions of the encrypted files on disk."""
    suffixes = []
    for path in app.config["BLOB_DIR"].iterdir():
        suffixes.append(path.suffix)
    suffixes.sort()
    return suffixes


def flip_byte(app, suffix: str, position: int) -> None:
    """Corrupt one byte of the first encrypted file with this extension."""
    for path in app.config["BLOB_DIR"].iterdir():
        if path.suffix == suffix:
            raw = bytearray(path.read_bytes())
            raw[position] ^= 0xFF
            path.write_bytes(bytes(raw))
            return
    raise FileNotFoundError(f"no {suffix} file")
