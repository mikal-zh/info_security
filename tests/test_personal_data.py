# PROJECT, 2026
# info_security
# File description:
# Personal-data tests: round trip and no plaintext at rest.

"""Personal-data tests: round trip and no plaintext at rest."""

import sqlite3

from tests.helpers import NIK, post_form, stored_bytes


def test_personal_data_roundtrip(client):
    """Saved fields come back, each with three verified copies."""
    post_form(client, "/personal-data", {"nik": NIK, "religion": "Islam"})
    page = client.get("/personal-data").get_data(as_text=True)
    assert f'value="{NIK}"' in page
    assert page.count("fa-circle-check") >= 6


def test_nothing_in_clear_and_three_distinct_copies(app, client):
    """Values never appear at rest, and the three copies all differ."""
    post_form(client, "/personal-data", {"nik": NIK, "religion": "Islam"})
    stored = stored_bytes(app)
    assert NIK.encode() not in stored and b"Islam" not in stored
    rows = sqlite3.connect(app.config["DB_PATH"]).execute(
        "SELECT aes, des, rc4 FROM personal_data").fetchall()
    assert len(rows) == 2 and all(len(set(row)) == 3 for row in rows)
