"""Storage and retrieval of an employee's personal data and documents.

Every item is sealed three times, once with each cipher (AES, DES, RC4), and
each copy is stored. On retrieval the copy is authenticated by its HMAC before
it is decrypted, and documents are also checked against the SHA-256 recorded
in their sealed metadata, so a user only ever gets back exactly what they
stored.
"""

import hashlib
import json
import sqlite3
import uuid as uuidlib
from dataclasses import dataclass
from pathlib import Path

from .catalog import FIELDS_BY_NAME
from .crypto import CIPHERS, IntegrityError, VaultKeys


def _field_ctx(user_id: int, field: str) -> str:
    return f"user:{user_id}|field:{field}"


def _doc_ctx(user_id: int, doc_uuid: str, part: str) -> str:
    return f"user:{user_id}|doc:{doc_uuid}|{part}"


def _blob_path(blob_dir: Path, doc_uuid: str, cipher: str) -> Path:
    return blob_dir / f"{doc_uuid}.{cipher.lower()}"


# ---------- personal data ---------- #

def save_personal_data(conn: sqlite3.Connection, user_id: int, keys: VaultKeys, values: dict[str, str]) -> None:
    for name, value in values.items():
        if name not in FIELDS_BY_NAME:
            raise ValueError(f"unknown field {name!r}")
        if not value:
            conn.execute("DELETE FROM personal_data WHERE user_id = ? AND field = ?", (user_id, name))
            continue
        ctx = _field_ctx(user_id, name)
        sealed = [keys.seal(c, value.encode(), ctx) for c in CIPHERS]
        conn.execute(
            """INSERT INTO personal_data (user_id, field, aes, des, rc4) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (user_id, field) DO UPDATE SET
                 aes = excluded.aes, des = excluded.des, rc4 = excluded.rc4,
                 updated_at = CURRENT_TIMESTAMP""",
            (user_id, name, *sealed),
        )
    conn.commit()


@dataclass
class FieldValue:
    value: str | None
    copies: dict[str, bool]   # cipher -> copy authenticated and decrypted
    consistent: bool          # all valid copies decrypt to the same value
    stored_bytes: dict[str, int]
    preview: dict[str, str]   # cipher -> hex of the first stored bytes, to show what is at rest

    @property
    def ok(self) -> bool:
        return self.consistent and all(self.copies.values())


def load_personal_data(conn: sqlite3.Connection, user_id: int, keys: VaultKeys) -> dict[str, FieldValue]:
    result = {}
    rows = conn.execute("SELECT * FROM personal_data WHERE user_id = ?", (user_id,))
    for row in rows:
        ctx = _field_ctx(user_id, row["field"])
        plain, copies = {}, {}
        for c in CIPHERS:
            try:
                plain[c] = keys.open(c, row[c.lower()], ctx).decode()
                copies[c] = True
            except (IntegrityError, UnicodeDecodeError):
                copies[c] = False
        values = set(plain.values())
        result[row["field"]] = FieldValue(
            value=plain.get("AES") or next(iter(values), None),
            copies=copies,
            consistent=len(values) == 1,
            stored_bytes={c: len(row[c.lower()]) for c in CIPHERS},
            preview={c: row[c.lower()][:20].hex() for c in CIPHERS},
        )
    return result


# ---------- documents ---------- #

def store_document(conn, blob_dir: Path, user_id: int, keys: VaultKeys,
                   category: str, filename: str, mime: str, data: bytes) -> str:
    doc_uuid = uuidlib.uuid4().hex
    meta = json.dumps({
        "filename": filename,
        "mime": mime,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }).encode()
    meta_ctx = _doc_ctx(user_id, doc_uuid, "meta")
    blob_ctx = _doc_ctx(user_id, doc_uuid, "blob")

    blob_dir.mkdir(parents=True, exist_ok=True)
    for c in CIPHERS:
        _blob_path(blob_dir, doc_uuid, c).write_bytes(keys.seal(c, data, blob_ctx))
    conn.execute(
        "INSERT INTO documents (user_id, uuid, category, meta_aes, meta_des, meta_rc4) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, doc_uuid, category, *[keys.seal(c, meta, meta_ctx) for c in CIPHERS]),
    )
    conn.commit()
    return doc_uuid


def _open_meta(row, user_id: int, keys: VaultKeys, cipher: str = "AES") -> dict:
    ctx = _doc_ctx(user_id, row["uuid"], "meta")
    return json.loads(keys.open(cipher, row[f"meta_{cipher.lower()}"], ctx))


def list_documents(conn, user_id: int, keys: VaultKeys) -> list[dict]:
    docs = []
    rows = conn.execute("SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC, id DESC", (user_id,))
    for row in rows:
        try:
            meta = _open_meta(row, user_id, keys)
        except IntegrityError:
            meta = {"filename": "(metadata failed integrity check)", "mime": "", "size": 0}
        docs.append({"id": row["id"], "category": row["category"], "created_at": row["created_at"], **meta})
    return docs


def _own_document(conn, user_id: int, doc_id: int):
    # Ownership is enforced in the query: another user's id simply is not found.
    return conn.execute("SELECT * FROM documents WHERE id = ? AND user_id = ?", (doc_id, user_id)).fetchone()


def read_document(conn, blob_dir: Path, user_id: int, keys: VaultKeys,
                  doc_id: int, cipher: str) -> tuple[dict, bytes] | None:
    """Return (metadata, plaintext) from the chosen cipher's copy.

    Raises IntegrityError if that copy (or its metadata) was altered.
    """
    if cipher not in CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")
    row = _own_document(conn, user_id, doc_id)
    if row is None:
        return None
    meta = _open_meta(row, user_id, keys, cipher)
    sealed = _blob_path(blob_dir, row["uuid"], cipher).read_bytes()
    data = keys.open(cipher, sealed, _doc_ctx(user_id, row["uuid"], "blob"))
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise IntegrityError("content does not match recorded SHA-256")
    return meta, data


def verify_document(conn, blob_dir: Path, user_id: int, keys: VaultKeys, doc_id: int) -> dict | None:
    """Check all three copies. Returns {cipher: (ok, stored_bytes or error)}."""
    row = _own_document(conn, user_id, doc_id)
    if row is None:
        return None
    report = {}
    for c in CIPHERS:
        path = _blob_path(blob_dir, row["uuid"], c)
        try:
            read_document(conn, blob_dir, user_id, keys, doc_id, c)
            report[c] = (True, path.stat().st_size)
        except (IntegrityError, OSError, ValueError) as exc:
            report[c] = (False, str(exc))
    return report


def delete_document(conn, blob_dir: Path, user_id: int, doc_id: int) -> bool:
    row = _own_document(conn, user_id, doc_id)
    if row is None:
        return False
    for c in CIPHERS:
        _blob_path(blob_dir, row["uuid"], c).unlink(missing_ok=True)
    conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    return True


def erase_user(conn, blob_dir: Path, user_id: int) -> None:
    """Right to erasure (GDPR Art. 17, UU PDP Pasal 8): remove every trace of the user."""
    for row in conn.execute("SELECT id FROM documents WHERE user_id = ?", (user_id,)).fetchall():
        delete_document(conn, blob_dir, user_id, row["id"])
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
