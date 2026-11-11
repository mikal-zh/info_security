# PROJECT, 2026
# info_security
# File description:
# Minimal ASN.1 DER encoder and decoder for certificates and CMS.

"""Minimal ASN.1 DER encoder and decoder.

Only what X.509 certificates and CMS SignedData need: every value is
written as tag | length | content, with the shortest length form. The
decoder returns the raw TLVs; callers know the structure they expect.
"""

from typing import NamedTuple

INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
UTC_TIME = 0x17
SEQUENCE = 0x30
SET = 0x31


class Tlv(NamedTuple):
    """One decoded value: tag, content bytes and the full encoding."""

    tag: int
    content: bytes
    encoded: bytes


def _length(size: int) -> bytes:
    """DER length octets: short form below 128, long form above."""
    if size < 0x80:
        return bytes([size])
    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def tlv(tag: int, content: bytes) -> bytes:
    """Encode one value with its tag and length."""
    return bytes([tag]) + _length(len(content)) + content


def integer(value: int) -> bytes:
    """A non-negative INTEGER, with a leading zero if the top bit is set."""
    size = value.bit_length() // 8 + 1
    return tlv(INTEGER, value.to_bytes(size, "big"))


def oid(dotted: str) -> bytes:
    """An OBJECT IDENTIFIER from its dotted form, e.g. "2.5.4.3"."""
    arcs = []
    for part in dotted.split("."):
        arcs.append(int(part))
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = bytes([arc & 0x7F])
        arc >>= 7
        while arc:
            chunk = bytes([0x80 | (arc & 0x7F)]) + chunk
            arc >>= 7
        body += chunk
    return tlv(OID, body)


def sequence(*items: bytes) -> bytes:
    """A SEQUENCE of already encoded items."""
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    """A SET OF already encoded items, sorted as DER requires."""
    return tlv(SET, b"".join(sorted(items)))


def read(data: bytes, pos: int = 0) -> Tlv:
    """Decode the value starting at `pos` (single-byte tags only)."""
    tag = data[pos]
    size = data[pos + 1]
    start = pos + 2
    if size & 0x80:
        count = size & 0x7F
        size = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + size
    if end > len(data):
        raise ValueError("DER value runs past the end of the data")
    return Tlv(tag, data[start:end], data[pos:end])


def children(content: bytes) -> list[Tlv]:
    """Decode the consecutive values inside a SEQUENCE or SET."""
    items = []
    pos = 0
    while pos < len(content):
        item = read(content, pos)
        items.append(item)
        pos += len(item.encoded)
    return items
