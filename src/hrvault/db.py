"""SQLite storage. Only ciphertext and non-personal bookkeeping are stored in clear."""

import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,   -- employee number, needed in clear to log in
    salt         BLOB NOT NULL,
    iterations   INTEGER NOT NULL,
    verifier     BLOB NOT NULL,          -- SHA-256 of the PBKDF2-derived login verifier
    wrapped_key  BLOB NOT NULL,          -- vault key, AES-256-GCM under the password KEK
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- One row per personal-data field, holding the value sealed under each cipher.
CREATE TABLE IF NOT EXISTS personal_data (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,
    aes        BLOB NOT NULL,
    des        BLOB NOT NULL,
    rc4        BLOB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, field)
);

-- File contents live on disk as <uuid>.<cipher>; filename, type, size and
-- SHA-256 are kept here in sealed metadata, also once per cipher.
CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    uuid        TEXT UNIQUE NOT NULL,
    category    TEXT NOT NULL,
    meta_aes    BLOB NOT NULL,
    meta_des    BLOB NOT NULL,
    meta_rc4    BLOB NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init(path) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def get() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()
