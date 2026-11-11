# PROJECT, 2026
# info_security
# File description:
# Reading the first intact copy of a document and replacing its content.

"""Reading the first intact copy of a document and replacing it.

Signing a PDF changes its bytes, so the three encrypted copies (AES,
DES, RC4) and their sealed metadata are rewritten with the new content,
using the same contexts as when the document was uploaded.
"""

import hashlib
import json

from . import documents
from .crypto import CIPHERS, IntegrityError
from .owner import Owner

UPDATE_META = """
UPDATE documents SET meta_aes = ?, meta_des = ?, meta_rc4 = ?
WHERE id = ? AND user_id = ?
"""


def first_intact_copy(owner: Owner, doc_id: int):
    """(metadata, data) from the first copy that verifies, else None."""
    for cipher in CIPHERS:
        try:
            return documents.read_document(owner, doc_id, cipher)
        except (IntegrityError, OSError):
            continue
    return None


def replace_content(owner: Owner, doc_id: int, meta: dict,
                    data: bytes) -> None:
    """Re-seal new content and metadata in all three copies."""
    row = documents.own_document(owner, doc_id)
    meta = {**meta, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
    blob_context = owner.context(f"doc:{row['uuid']}|blob")
    meta_context = owner.context(f"doc:{row['uuid']}|meta")
    sealed_metas = []
    for cipher in CIPHERS:
        sealed = owner.keys.seal(cipher, data, blob_context)
        documents.blob_path(owner, row["uuid"], cipher).write_bytes(sealed)
        sealed_metas.append(owner.keys.seal(cipher, json.dumps(meta).encode(),
                                            meta_context))
    owner.conn.execute(UPDATE_META, (*sealed_metas, doc_id, owner.user_id))
    owner.conn.commit()
