# PROJECT, 2026
# info_security
# File description:
# Embedding a digital signature in a PDF with an incremental update.

"""Embedding a digital signature in a PDF (ISO 32000-1, section 12.8).

The signature is added as an incremental update holding:

* a signature dictionary (/Type /Sig, /SubFilter /adbe.pkcs7.detached)
  whose /Contents is a placeholder and whose /ByteRange lists the two
  byte ranges around that placeholder;
* an invisible signature field (widget annotation) pointing to it,
  with an empty appearance stream;
* new versions of the first page (annotation added) and of the
  catalog (/AcroForm with the field and /SigFlags 3).

Once the file is assembled, the SHA-256 of the covered byte ranges is
signed (CMS, see `cms.py`) and the CMS bytes are written in hex into the
placeholder. Any PDF reader can then recompute the hash and check it.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from . import cms
from .pdf_document import PdfDocument
from .pdf_lexer import Name, PdfError, Ref
from .pdf_update import IncrementalUpdate
from .pdf_writer import serialize

CONTENTS_SIZE = 16384
BYTE_RANGE_PLACEHOLDER = b"[0 0 0 0" + b" " * 40 + b"]"
INVISIBLE = [0, 0, 0, 0]
PRINT_AND_LOCKED = 132
SIGNATURES_EXIST_APPEND_ONLY = 3


@dataclass(frozen=True)
class Signer:
    """Who signs: private key, DER certificate, name and reason."""

    private_key: object
    certificate: bytes
    name: str
    reason: str


def _signature_dictionary(signer: Signer, when: datetime) -> bytes:
    """The /Sig dictionary with ByteRange and Contents placeholders."""
    date = when.strftime("D:%Y%m%d%H%M%S+00'00'").encode()
    return (b"<</Type /Sig /Filter /Adobe.PPKLite"
            b" /SubFilter /adbe.pkcs7.detached"
            b" /ByteRange " + BYTE_RANGE_PLACEHOLDER
            + b" /Contents <" + b"0" * (CONTENTS_SIZE * 2) + b">"
            + b" /M " + serialize(date)
            + b" /Name " + serialize(signer.name.encode())
            + b" /Reason " + serialize(signer.reason.encode()) + b">>")


def _empty_appearance() -> bytes:
    """An empty form XObject: the look of an invisible signature."""
    info = {"Type": Name("XObject"), "Subtype": Name("Form"),
            "BBox": INVISIBLE, "Length": 0}
    return serialize(info) + b"\nstream\n\nendstream"


def _widget(signature: Ref, page: Ref, appearance: Ref) -> dict:
    """An invisible signature field merged with its widget annotation."""
    return {"Type": Name("Annot"), "Subtype": Name("Widget"),
            "FT": Name("Sig"), "Rect": INVISIBLE, "F": PRINT_AND_LOCKED,
            "T": f"Signature{signature.number}".encode(), "V": signature,
            "P": page, "AP": {"N": appearance}}


def _list(document: PdfDocument, value) -> list:
    """A copy of an array that may be indirect or missing."""
    resolved = document.resolve(value)
    if isinstance(resolved, list):
        return list(resolved)
    return []


def _with_form_field(document: PdfDocument, widget: Ref) -> dict:
    """A copy of the catalog whose /AcroForm lists the new field."""
    catalog = dict(document.catalog())
    form = document.resolve(catalog.get("AcroForm"))
    if not isinstance(form, dict):
        form = {}
    form = dict(form)
    form["Fields"] = _list(document, form.get("Fields")) + [widget]
    form["SigFlags"] = SIGNATURES_EXIST_APPEND_ONLY
    catalog["AcroForm"] = form
    return catalog


def _with_placeholder(pdf: bytes, signer: Signer,
                      when: datetime) -> bytearray:
    """The PDF with the signature objects and empty /Contents."""
    document = PdfDocument(pdf)
    update = IncrementalUpdate(document)
    signature, widget = update.new_ref(), update.new_ref()
    appearance = update.new_ref()
    page_ref, page = document.first_page()
    update.put(signature, _signature_dictionary(signer, when))
    update.put(appearance, _empty_appearance())
    update.put(widget, serialize(_widget(signature, page_ref, appearance)))
    page = dict(page)
    page["Annots"] = _list(document, page.get("Annots")) + [widget]
    update.put(page_ref, serialize(page))
    update.put(document.trailer["Root"],
               serialize(_with_form_field(document, widget)))
    return update.build()


def _byte_range(output: bytearray) -> tuple[int, int]:
    """Fill /ByteRange; return the start and end of the hex /Contents."""
    contents = output.rfind(b"/Contents <") + len(b"/Contents ")
    end = output.index(b">", contents) + 1
    ranges = f"[0 {contents} {end} {len(output) - end}".encode()
    ranges = ranges.ljust(len(BYTE_RANGE_PLACEHOLDER) - 1) + b"]"
    position = output.rfind(b"/ByteRange ") + len(b"/ByteRange ")
    output[position:position + len(ranges)] = ranges
    return contents, end


def sign_pdf(pdf: bytes, signer: Signer) -> bytes:
    """Return a copy of `pdf` carrying an embedded signature."""
    when = datetime.now(timezone.utc).replace(microsecond=0)
    output = _with_placeholder(pdf, signer, when)
    start, end = _byte_range(output)
    digest = hashlib.sha256(output[:start] + output[end:]).digest()
    signed = cms.sign_detached(signer.private_key, signer.certificate,
                               digest, when)
    hex_value = signed.hex().encode()
    if len(hex_value) > CONTENTS_SIZE * 2:
        raise PdfError("signature does not fit in the reserved space")
    output[start + 1:start + 1 + len(hex_value)] = hex_value
    return bytes(output)
