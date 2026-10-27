# PROJECT, 2026
# info_security
# File description:
# End-to-end download timings through the Flask app.

"""End-to-end download timings through the Flask app.

Each request goes through the test client (no network): read from disk,
HMAC check, decryption, SHA-256 check and response. This shows what share
of a real request is spent in the cipher.
"""

import os
import re
import tempfile
from functools import partial
from pathlib import Path

from timing import summarise, time_ns
from workloads import FILE_WORKLOADS, repeats_for

from hrvault import accounts, create_app, db, documents
from hrvault.crypto import CIPHERS
from hrvault.owner import Owner

USER = accounts.Credentials("bench", "benchmark-pass")
FAST_ITERATIONS = 1000
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _store_workloads(app) -> dict[str, int]:
    """Create the benchmark user and store one file per workload."""
    with app.app_context():
        conn = db.get()
        accounts.register(conn, USER, FAST_ITERATIONS)
        user_id, keys = accounts.login(conn, USER, FAST_ITERATIONS)
        owner = Owner(conn, app.config["BLOB_DIR"], user_id, keys)
        ids = {}
        for name, size, _ in FILE_WORKLOADS:
            upload = documents.Upload("office", f"{name}.bin",
                                      "application/octet-stream",
                                      os.urandom(size))
            documents.store_document(owner, upload)
            ids[name] = conn.execute(
                "SELECT MAX(id) FROM documents").fetchone()[0]
    return ids


def _logged_in_client(app):
    """A test client logged in as the benchmark user."""
    client = app.test_client()
    html = client.get("/login").get_data(as_text=True)
    form = {"username": USER.username, "password": USER.password,
            "csrf_token": CSRF_RE.search(html).group(1)}
    client.post("/login", data=form)
    return client


def _fetch(client, url: str) -> bytes:
    """Download one URL completely."""
    return client.get(url).get_data()


def bench_download(quick: bool) -> list[dict]:
    """Median download time of each file workload from each copy."""
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app({"DATA_DIR": Path(tmp),
                          "PBKDF2_ITERATIONS": FAST_ITERATIONS})
        ids = _store_workloads(app)
        client = _logged_in_client(app)
        for name, size, _ in FILE_WORKLOADS:
            for cipher in CIPHERS:
                url = f"/documents/{ids[name]}/download?cipher={cipher}"
                samples = time_ns(partial(_fetch, client, url),
                                  repeats_for(size, quick), warmup=2)
                rows.append({"workload": name, "bytes": size,
                             "cipher": cipher, **summarise(samples)})
    return rows
