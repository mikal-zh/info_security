# PROJECT, 2026
# info_security
# File description:
# Storage, retrieval and verification of uploaded documents.

"""Uploaded documents, each stored as three sealed copies.

File contents live on disk as <uuid>.aes / .des / .rc4. Filename, MIME
type, size and SHA-256 are kept in sealed metadata, also once per
cipher. On retrieval a copy is authenticated by its HMAC and compared
with the recorded SHA-256, so a user only ever gets back exactly what
they stored.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass

from .crypto import CIPHERS, IntegrityError
from .owner import Owner

INSERT = """
INSERT INTO documents (user_id, uuid, category, meta_aes, meta_des, meta_rc4)
VALUES (?, ?, ?, ?, ?, ?)
"""


@dataclass(frozen=True)
class Upload:
    """A file submitted by the user, before encryption."""

    category: str
    filename: str
    mime: str
    data: bytes


def _blob_path(owner: Owner, doc_uuid: str, cipher: str):
    """Disk path of one encrypted copy; it reveals neither name nor owner."""
    return owner.blob_dir / f"{doc_uuid}.{cipher.lower()}"


def _metadata(upload: Upload) -> bytes:
    """JSON metadata kept sealed next to the file: name, type, size, hash."""
    return json.dumps({
        "filename": upload.filename, "mime": upload.mime,
        "size": len(upload.data),
        "sha256": hashlib.sha256(upload.data).hexdigest(),
    }).encode()


def store_document(owner: Owner, upload: Upload) -> str:
    """Seal the file and its metadata with all three ciphers.

    Returns the random UUID that names the document's files on disk.
    """
    doc_uuid = uuid.uuid4().hex
    meta = _metadata(upload)
    owner.blob_dir.mkdir(parents=True, exist_ok=True)
    blob_ctx = owner.context(f"doc:{doc_uuid}|blob")
    meta_ctx = owner.context(f"doc:{doc_uuid}|meta")
    for cipher in CIPHERS:
        sealed = owner.keys.seal(cipher, upload.data, blob_ctx)
        _blob_path(owner, doc_uuid, cipher).write_bytes(sealed)
    metas = [owner.keys.seal(cipher, meta, meta_ctx) for cipher in CIPHERS]
    owner.conn.execute(INSERT, (owner.user_id, doc_uuid, upload.category,
                                *metas))
    owner.conn.commit()
    return doc_uuid


def _open_meta(owner: Owner, row, cipher: str = "AES") -> dict:
    """Verify and decode the metadata copy of the given cipher."""
    context = owner.context(f"doc:{row['uuid']}|meta")
    sealed = row[f"meta_{cipher.lower()}"]
    return json.loads(owner.keys.open(cipher, sealed, context))


def list_documents(owner: Owner) -> list[dict]:
    """The owner's documents, newest first, with decrypted metadata."""
    rows = owner.conn.execute(
        "SELECT * FROM documents WHERE user_id = ? "
        "ORDER BY created_at DESC, id DESC", (owner.user_id,))
    docs = []
    for row in rows:
        try:
            meta = _open_meta(owner, row)
        except IntegrityError:
            meta = {"filename": "(metadata failed integrity check)",
                    "mime": "", "size": 0}
        docs.append({"id": row["id"], "category": row["category"],
                     "created_at": row["created_at"], **meta})
    return docs


def _own_document(owner: Owner, doc_id: int):
    """The document row, or None if it does not belong to the owner."""
    return owner.conn.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, owner.user_id)).fetchone()


def read_document(owner: Owner, doc_id: int, cipher: str):
    """Return (metadata, plaintext) from the chosen cipher's copy.

    Returns None for a document the owner does not have. Raises
    IntegrityError if that copy or its metadata was altered.
    """
    if cipher not in CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")
    row = _own_document(owner, doc_id)
    if row is None:
        return None
    meta = _open_meta(owner, row, cipher)
    sealed = _blob_path(owner, row["uuid"], cipher).read_bytes()
    context = owner.context(f"doc:{row['uuid']}|blob")
    data = owner.keys.open(cipher, sealed, context)
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise IntegrityError("content does not match recorded SHA-256")
    return meta, data


def verify_document(owner: Owner, doc_id: int) -> dict | None:
    """Check all three copies: {cipher: (ok, size on disk or error)}."""
    row = _own_document(owner, doc_id)
    if row is None:
        return None
    report = {}
    for cipher in CIPHERS:
        try:
            read_document(owner, doc_id, cipher)
            size = _blob_path(owner, row["uuid"], cipher).stat().st_size
            report[cipher] = (True, size)
        except (IntegrityError, OSError, ValueError) as exc:
            report[cipher] = (False, str(exc))
    return report


def delete_document(owner: Owner, doc_id: int) -> bool:
    """Delete the row and its three files; False if not the owner's."""
    row = _own_document(owner, doc_id)
    if row is None:
        return False
    for cipher in CIPHERS:
        _blob_path(owner, row["uuid"], cipher).unlink(missing_ok=True)
    owner.conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    owner.conn.commit()
    return True


def erase_user(owner: Owner) -> None:
    """Right to erasure (GDPR Art. 17, UU PDP Pasal 8): remove everything."""
    rows = owner.conn.execute(
        "SELECT id FROM documents WHERE user_id = ?",
        (owner.user_id,)).fetchall()
    for row in rows:
        delete_document(owner, row["id"])
    owner.conn.execute("DELETE FROM users WHERE id = ?", (owner.user_id,))
    owner.conn.commit()
