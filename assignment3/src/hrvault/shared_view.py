# PROJECT, 2026
# info_security
# File description:
# The requester's side of a share: unwrap the key and read the copy.

"""Reading a file someone shared with you.

The requester's private key (opened with their own vault key) decrypts
the wrapped share key, which then opens the shared copy. Every item is
authenticated by its HMAC before it is shown or downloaded.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import keypairs
from .catalog import FIELDS
from .crypto import IntegrityError, VaultKeys, rsa_keys
from .owner import Owner
from .share_snapshot import SHARE_CIPHER, shared_blob_path

RECEIVED = """
SELECT r.*, u.username AS owner_name FROM access_requests r
JOIN users u ON u.id = r.owner_id
WHERE r.id = ? AND r.requester_id = ? AND r.status = 'approved'
"""


@dataclass(frozen=True)
class Share:
    """An opened share: its request row, share keys and file folder."""

    conn: object
    row: object
    keys: VaultKeys
    share_dir: Path

    @property
    def request_id(self) -> int:
        """Id of the access request this share belongs to."""
        return self.row["id"]


def open_share(owner: Owner, request_id: int, share_dir) -> Share | None:
    """Unwrap the share key of an approved request made by `owner`."""
    row = owner.conn.execute(RECEIVED, (request_id,
                                        owner.user_id)).fetchone()
    if row is None:
        return None
    private_key = keypairs.load_private_key(owner)
    if private_key is None:
        raise IntegrityError("no private key to unwrap the share key")
    share_key = rsa_keys.decrypt_with(private_key, row["wrapped_key"])
    return Share(owner.conn, row, VaultKeys(share_key), Path(share_dir))


def shared_fields(share: Share) -> list[tuple[str, str]]:
    """(label, value) of every shared field, in form order."""
    rows = share.conn.execute(
        "SELECT field, sealed FROM shared_fields WHERE request_id = ?",
        (share.request_id,)).fetchall()
    sealed_by_name = {}
    for row in rows:
        sealed_by_name[row["field"]] = row["sealed"]
    shown = []
    for field in FIELDS:
        if field.name not in sealed_by_name:
            continue
        context = f"share:{share.request_id}|field:{field.name}"
        plain = share.keys.open(SHARE_CIPHER, sealed_by_name[field.name],
                                context)
        shown.append((field.label, plain.decode()))
    return shown


def _open_meta(share: Share, row) -> dict:
    """Verify and decode a shared document's metadata."""
    context = f"share:{share.request_id}|doc:{row['uuid']}|meta"
    return json.loads(share.keys.open(SHARE_CIPHER, row["meta"], context))


def shared_documents(share: Share) -> list[dict]:
    """The shared documents with their decrypted metadata."""
    rows = share.conn.execute(
        "SELECT * FROM shared_documents WHERE request_id = ? ORDER BY id",
        (share.request_id,)).fetchall()
    docs = []
    for row in rows:
        meta = _open_meta(share, row)
        docs.append({"id": row["id"], "category": row["category"], **meta})
    return docs


def read_shared_document(share: Share, doc_id: int):
    """(metadata, data) of one shared document, or None if not shared.

    Raises IntegrityError if the copy was altered.
    """
    row = share.conn.execute(
        "SELECT * FROM shared_documents WHERE id = ? AND request_id = ?",
        (doc_id, share.request_id)).fetchone()
    if row is None:
        return None
    meta = _open_meta(share, row)
    sealed = shared_blob_path(share.share_dir, row["uuid"]).read_bytes()
    context = f"share:{share.request_id}|doc:{row['uuid']}|blob"
    data = share.keys.open(SHARE_CIPHER, sealed, context)
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise IntegrityError("content does not match recorded SHA-256")
    return meta, data
