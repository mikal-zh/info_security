# PROJECT, 2026
# info_security
# File description:
# Signing a stored PDF with its owner's key and checking its signatures.

"""Signing a stored PDF with its owner's private key, and checking it.

Signing reads the first intact encrypted copy, embeds the signature
with `pdfsign.signer`, and stores the signed PDF back as three new
encrypted copies. If the owner has no key pair yet, one is generated
first. Checking runs `pdfsign.verifier` and says, for each signature,
which registered user's key made it.
"""

from dataclasses import dataclass

from . import document_copies, documents, keypairs
from .owner import Owner
from .pdfsign import signer, verifier
from .pdfsign.pdf_lexer import PdfError

PDF_MIME = "application/pdf"
SIGN_REASON = "Signed in Onboarding Vault"


class SigningError(Exception):
    """A user-facing reason why a document could not be signed."""


@dataclass
class SigningResult:
    """The signed document's name and whether a key pair was created."""

    filename: str
    key_created: bool


def _signer_for(owner: Owner) -> signer.Signer:
    """The owner's private key, certificate and employee number."""
    cert = keypairs.certificate_of(owner.conn, owner.user_id)
    name = keypairs.username_for_key(
        owner.conn, keypairs.public_key_of(owner.conn, owner.user_id))
    return signer.Signer(keypairs.load_private_key(owner), cert, name,
                         SIGN_REASON)


def _owned_pdf(owner: Owner, doc_id: int):
    """(metadata, data) of the owner's PDF; None if not theirs."""
    if documents.own_document(owner, doc_id) is None:
        return None
    found = document_copies.first_intact_copy(owner, doc_id)
    if found is None:
        raise SigningError("Every copy of this document failed its "
                           "integrity check.")
    if found[0]["mime"] != PDF_MIME:
        raise SigningError("Only PDF documents can be signed.")
    return found


def sign_document(owner: Owner, doc_id: int, bits: int):
    """Sign one of the owner's PDFs; None if the document is not theirs."""
    found = _owned_pdf(owner, doc_id)
    if found is None:
        return None
    meta, data = found
    created = keypairs.ensure_key_pair(owner, bits)
    try:
        signed = signer.sign_pdf(data, _signer_for(owner))
    except (PdfError, ValueError, IndexError, KeyError) as exc:
        raise SigningError(f"We couldn't sign this PDF: {exc}.") from exc
    document_copies.replace_content(owner, doc_id, {**meta, "signed": True},
                                    signed)
    return SigningResult(meta["filename"], created)


def check_pdf(conn, data: bytes) -> list[verifier.SignatureCheck]:
    """Check every signature and name the registered user who made it."""
    checks = verifier.verify_pdf(data)
    for check in checks:
        check.registered_user = keypairs.username_for_key(conn,
                                                          check.public_key)
    return checks


def check_document(owner: Owner, doc_id: int):
    """(metadata, checks) of one of the owner's PDFs; None if not theirs."""
    found = _owned_pdf(owner, doc_id)
    if found is None:
        return None
    meta, data = found
    return meta, check_pdf(owner.conn, data)
