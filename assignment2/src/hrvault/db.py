# PROJECT, 2026
# info_security
# File description:
# SQLite schema and connection handling.

"""SQLite storage.

Only ciphertext and non-personal bookkeeping are stored in clear. The
employee number is kept in clear because it is needed to log in.
"""

import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    salt         BLOB NOT NULL,
    iterations   INTEGER NOT NULL,
    verifier     BLOB NOT NULL,
    wrapped_key  BLOB NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS personal_data (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,
    aes        BLOB NOT NULL,
    des        BLOB NOT NULL,
    rc4        BLOB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, field)
);

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
    """Open a connection with dict-like rows and foreign keys enforced."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init(path) -> None:
    """Create the tables if they do not exist yet."""
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def get() -> sqlite3.Connection:
    """The connection for the current request, opened on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close(_exc=None) -> None:
    """Close the request's connection, if one was opened."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()
