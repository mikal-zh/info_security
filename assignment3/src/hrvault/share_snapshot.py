# PROJECT, 2026
# info_security
# File description:
# Approving a request: re-seal the owner's file under a share key.

"""Approving, revoking and erasing shares.

On approval, while the owner is logged in (so their vault key is in
memory), the server:

1. draws a fresh random 32-byte *share key*;
2. re-seals every personal-data field and every document under that
   key with the AES encrypt-then-MAC envelope, bound to the request id;
3. encrypts the share key with the requester's RSA public key
   (RSA-OAEP, SHA-256) and stores only that wrapped key.

The owner's own vault key never leaves the owner's account, and only
the requester's private key can unwrap the share key. Revoking deletes
the shared copy, so the wrapped key no longer opens anything.
"""

import json
import uuid

from . import document_copies, documents, keypairs, personal, sharing
from .crypto import VaultKeys, rsa_keys
from .owner import Owner

SHARE_CIPHER = "AES"
INSERT_FIELD = """
INSERT INTO shared_fields (request_id, field, sealed) VALUES (?, ?, ?)
"""
INSERT_DOCUMENT = """
INSERT INTO shared_documents (request_id, uuid, category, meta)
VALUES (?, ?, ?, ?)
"""


def shared_blob_path(share_dir, doc_uuid: str):
    """Disk path of a shared document's encrypted content."""
    return share_dir / f"{doc_uuid}.{SHARE_CIPHER.lower()}"


def _seal_fields(owner: Owner, share_keys: VaultKeys,
                 request_id: int) -> None:
    """Copy every readable personal-data field under the share key."""
    fields = personal.load_personal_data(owner)
    for name, field in fields.items():
        if field.value is None:
            continue
        context = f"share:{request_id}|field:{name}"
        sealed = share_keys.seal(SHARE_CIPHER, field.value.encode(), context)
        owner.conn.execute(INSERT_FIELD, (request_id, name, sealed))


def _seal_document(owner: Owner, share_keys: VaultKeys, doc: dict,
                   share: tuple) -> None:
    """Copy one document under the share key; share = (id, folder)."""
    request_id, share_dir = share
    found = document_copies.first_intact_copy(owner, doc["id"])
    if found is None:
        return
    meta, data = found
    doc_uuid = uuid.uuid4().hex
    context = f"share:{request_id}|doc:{doc_uuid}"
    blob = share_keys.seal(SHARE_CIPHER, data, context + "|blob")
    shared_blob_path(share_dir, doc_uuid).write_bytes(blob)
    sealed_meta = share_keys.seal(SHARE_CIPHER, json.dumps(meta).encode(),
                                  context + "|meta")
    owner.conn.execute(INSERT_DOCUMENT, (request_id, doc_uuid,
                                         doc["category"], sealed_meta))


def approve(owner: Owner, request_id: int, share_dir) -> bool:
    """Share the owner's file with the requester; False if not allowed."""
    row = sharing.owned_request(owner.conn, request_id, owner.user_id)
    if row is None or row["status"] != "pending":
        return False
    public = keypairs.public_key_of(owner.conn, row["requester_id"])
    if public is None:
        raise sharing.SharingError("The requester has no key pair yet.")
    share_keys = VaultKeys.generate()
    _seal_fields(owner, share_keys, request_id)
    for doc in documents.list_documents(owner):
        _seal_document(owner, share_keys, doc, (request_id, share_dir))
    wrapped = rsa_keys.encrypt_for(public, share_keys.vault_key)
    sharing.set_status(owner.conn, request_id, "approved", wrapped)
    return True


def _delete_copy(conn, request_id: int, share_dir) -> None:
    """Remove a share's encrypted files and rows."""
    rows = conn.execute("SELECT uuid FROM shared_documents "
                        "WHERE request_id = ?", (request_id,)).fetchall()
    for row in rows:
        shared_blob_path(share_dir, row["uuid"]).unlink(missing_ok=True)
    conn.execute("DELETE FROM shared_documents WHERE request_id = ?",
                 (request_id,))
    conn.execute("DELETE FROM shared_fields WHERE request_id = ?",
                 (request_id,))


def decide(owner: Owner, request_id: int, decision: str, share_dir) -> bool:
    """Reject a pending request or revoke an approved one.

    Both delete any shared copy; False if the request is not the
    owner's or is not in the right state.
    """
    expected = {"rejected": "pending", "revoked": "approved"}
    row = sharing.owned_request(owner.conn, request_id, owner.user_id)
    if row is None or row["status"] != expected.get(decision):
        return False
    _delete_copy(owner.conn, request_id, share_dir)
    sharing.set_status(owner.conn, request_id, decision)
    return True


def erase_user_shares(conn, user_id: int, share_dir) -> None:
    """Delete every share the user gave or received, files included."""
    rows = conn.execute(
        "SELECT id FROM access_requests WHERE owner_id = ? "
        "OR requester_id = ?", (user_id, user_id)).fetchall()
    for row in rows:
        _delete_copy(conn, row["id"], share_dir)
    conn.commit()
