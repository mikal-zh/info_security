# PROJECT, 2026
# info_security
# File description:
# Serialising Python values back to PDF object syntax.

"""Serialising Python values back to PDF object syntax.

Strings are always written in hexadecimal form, which is valid for any
bytes and needs no escaping.
"""

from .pdf_lexer import DELIMITERS, Name, PdfError, Ref, Stream


def name(value: str) -> bytes:
    """A /Name, with #xx escapes for characters that are not regular."""
    output = b"/"
    for byte in value.encode("latin-1"):
        if 0x21 <= byte <= 0x7E and byte not in DELIMITERS and byte != 0x23:
            output += bytes([byte])
        else:
            output += f"#{byte:02X}".encode()
    return output


def number(value) -> bytes:
    """An integer, or a real without exponent notation."""
    if isinstance(value, int):
        return str(value).encode()
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    if text in ("", "-", "-0"):
        text = "0"
    return text.encode()


def _container(value) -> bytes:
    """An array or a dictionary."""
    if isinstance(value, list):
        items = []
        for item in value:
            items.append(serialize(item))
        return b"[" + b" ".join(items) + b"]"
    pairs = []
    for key, item in value.items():
        pairs.append(name(key) + b" " + serialize(item))
    return b"<<" + b" ".join(pairs) + b">>"


def serialize(value) -> bytes:
    """PDF syntax of a direct value (streams must be written apart)."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, Name):
        return name(value)
    if isinstance(value, Ref):
        return f"{value.number} {value.generation} R".encode()
    if isinstance(value, (int, float)):
        return number(value)
    if isinstance(value, (bytes, bytearray)):
        return b"<" + bytes(value).hex().encode() + b">"
    if isinstance(value, (list, dict)):
        return _container(value)
    if isinstance(value, Stream):
        raise PdfError("a stream cannot be written as a direct value")
    return serialize(str(value).encode("latin-1"))
