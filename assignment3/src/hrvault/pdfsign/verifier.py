# PROJECT, 2026
# info_security
# File description:
# Checking every digital signature embedded in a PDF.

"""Checking every digital signature embedded in a PDF.

For each signature field the verifier:

1. takes the bytes listed in /ByteRange (everything except /Contents);
2. recomputes their SHA-256 and compares it with the signed
   messageDigest attribute (has the document changed?);
3. checks the RSA signature over the signed attributes with the public
   key of the certificate (did that key really sign it?);
4. reports whether the signature covers the whole file, or whether
   bytes were appended after signing.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from ..crypto import pkcs1
from . import certificate_info, cms_reader
from .pdf_document import PdfDocument
from .pdf_lexer import PdfError

MAX_FIELDS = 500


@dataclass
class SignatureCheck:
    """The outcome of checking one signature field."""

    field_name: str
    signer: str = ""
    signed_at: datetime | None = None
    public_key: bytes = b""
    intact: bool = False
    authentic: bool = False
    whole_file: bool = False
    certificate_ok: bool = False
    registered_user: str | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """True if the content is unchanged and the signature matches."""
        return self.intact and self.authentic


def signature_fields(document: PdfDocument) -> list[tuple[str, dict]]:
    """(field name, signature dictionary) of every signed field."""
    form = document.resolve(document.catalog().get("AcroForm"))
    if not isinstance(form, dict):
        return []
    pending = list(document.resolve(form.get("Fields")) or [])
    found = []
    while pending and len(found) < MAX_FIELDS:
        item = document.resolve(pending.pop(0))
        if not isinstance(item, dict):
            continue
        pending += list(document.resolve(item.get("Kids")) or [])
        value = document.resolve(item.get("V"))
        if item.get("FT") == "Sig" and isinstance(value, dict):
            label = item.get("T", b"Signature")
            found.append((bytes(label).decode("latin-1"), value))
    return found


def covered_bytes(data: bytes, byte_range: list) -> bytes:
    """The bytes a /ByteRange covers; PdfError if it is malformed."""
    if len(byte_range) != 4 or byte_range[0] != 0:
        raise PdfError("malformed /ByteRange")
    _, gap_start, gap_end, tail = byte_range
    if not 0 < gap_start < gap_end or gap_end + tail > len(data):
        raise PdfError("/ByteRange points outside the file")
    if data[gap_start:gap_start + 1] != b"<" or data[gap_end - 1] != 0x3E:
        raise PdfError("/ByteRange does not frame the signature value")
    return data[:gap_start] + data[gap_end:gap_end + tail]


def _check_crypto(check: SignatureCheck, signed, covered: bytes) -> None:
    """Fill the digest, signature and certificate results."""
    cert = signed.certificate
    check.signer = cert.subject
    check.signed_at = signed.signing_time
    check.public_key = cert.public_key
    digest = hashlib.sha256(covered).digest()
    check.intact = signed.sha256 and digest == signed.message_digest
    try:
        pkcs1.verify(certificate_info.public_key(cert),
                     signed.signed_attributes, signed.signature)
        check.authentic = True
    except (pkcs1.SignatureError, ValueError):
        check.problems.append("the RSA signature does not match")
    moment = signed.signing_time or cert.not_before
    check.certificate_ok = (certificate_info.is_self_signed_by_its_key(cert)
                            and certificate_info.valid_at(cert, moment))
    if not check.intact:
        check.problems.append("the document changed after signing")


def check_signature(data: bytes, name: str, signature: dict):
    """Check one signature dictionary against the file bytes."""
    check = SignatureCheck(name)
    try:
        covered = covered_bytes(data, signature.get("ByteRange", []))
        signed = cms_reader.parse(bytes(signature.get("Contents", b"")))
    except (PdfError, ValueError, IndexError, KeyError, TypeError) as exc:
        check.problems.append(f"unreadable signature ({exc})")
        return check
    range_end = signature["ByteRange"][2] + signature["ByteRange"][3]
    check.whole_file = range_end == len(data)
    _check_crypto(check, signed, covered)
    return check


def verify_pdf(data: bytes) -> list[SignatureCheck]:
    """Check every signature of a PDF; [] if it has none."""
    document = PdfDocument(data)
    checks = []
    for name, signature in signature_fields(document):
        checks.append(check_signature(data, name, signature))
    return checks
