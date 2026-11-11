# PROJECT, 2026
# info_security
# File description:
# Access requests between employees: create, list and decide.

"""Access requests between employees.

A requester asks for another employee's onboarding file by employee
number. The request stays *pending* until the owner either *rejects* it
or *approves* it (see `share_snapshot.py`). An approved share can later
be *revoked* by the owner.
"""

import sqlite3

from . import keypairs
from .crypto import rsa_keys

OPEN_STATUSES = ("pending", "approved")
INCOMING = """
SELECT r.*, u.username AS other, u.id AS other_id
FROM access_requests r
JOIN users u ON u.id = r.requester_id
WHERE r.owner_id = ? ORDER BY r.id DESC
"""
OUTGOING = """
SELECT r.*, u.username AS other, u.id AS other_id
FROM access_requests r
JOIN users u ON u.id = r.owner_id
WHERE r.requester_id = ? ORDER BY r.id DESC
"""
OPEN_REQUEST = """
SELECT 1 FROM access_requests
WHERE requester_id = ? AND owner_id = ? AND status IN (?, ?)
"""


class SharingError(Exception):
    """A user-facing reason why a sharing action was refused."""


def _user_id(conn: sqlite3.Connection, username: str) -> int | None:
    """Id of the account with this employee number, or None."""
    row = conn.execute("SELECT id FROM users WHERE username = ?",
                       (username,)).fetchone()
    if row is None:
        return None
    return row["id"]


def request_access(conn: sqlite3.Connection, requester_id: int,
                   owner_username: str) -> int:
    """Ask for an employee's file; return the new request's id."""
    owner_id = _user_id(conn, owner_username)
    if owner_id is None:
        raise SharingError("No employee has that number.")
    if owner_id == requester_id:
        raise SharingError("That's you! Your own file is already yours.")
    found = conn.execute(OPEN_REQUEST, (requester_id, owner_id,
                                        *OPEN_STATUSES)).fetchone()
    if found is not None:
        raise SharingError("You already have an open request for "
                           f"{owner_username}.")
    cur = conn.execute("INSERT INTO access_requests (requester_id, "
                       "owner_id) VALUES (?, ?)", (requester_id, owner_id))
    conn.commit()
    return cur.lastrowid


def _with_fingerprints(conn: sqlite3.Connection, rows) -> list[dict]:
    """Requests as dicts, with the other party's key fingerprint."""
    requests = []
    for row in rows:
        request = dict(row)
        public = keypairs.public_key_of(conn, row["other_id"])
        request["fingerprint"] = None
        if public is not None:
            request["fingerprint"] = rsa_keys.fingerprint(public)
        requests.append(request)
    return requests


def incoming(conn: sqlite3.Connection, owner_id: int) -> list[dict]:
    """Requests other employees made for this owner's file."""
    rows = conn.execute(INCOMING, (owner_id,)).fetchall()
    return _with_fingerprints(conn, rows)


def outgoing(conn: sqlite3.Connection, requester_id: int) -> list[dict]:
    """Requests this employee made for other employees' files."""
    rows = conn.execute(OUTGOING, (requester_id,)).fetchall()
    return _with_fingerprints(conn, rows)


def owned_request(conn: sqlite3.Connection, request_id: int,
                  owner_id: int):
    """The request row if it targets this owner's file, else None."""
    return conn.execute(
        "SELECT * FROM access_requests WHERE id = ? AND owner_id = ?",
        (request_id, owner_id)).fetchone()


def set_status(conn: sqlite3.Connection, request_id: int, status: str,
               wrapped_key: bytes | None = None) -> None:
    """Record the owner's decision (and the wrapped share key)."""
    conn.execute(
        "UPDATE access_requests SET status = ?, wrapped_key = ?, "
        "decided_at = CURRENT_TIMESTAMP WHERE id = ?",
        (status, wrapped_key, request_id))
    conn.commit()
