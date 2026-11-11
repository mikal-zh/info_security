# PROJECT, 2026
# info_security
# File description:
# Cross-reference reading: tables, streams, /Prev chains and recovery.

"""Cross-reference reading (ISO 32000-1, sections 7.5.4 to 7.5.8).

The cross-reference tells where each object lives: entry type 1 is a
byte offset in the file, type 2 is an index inside an object stream,
type 0 is a free (deleted) object. Sections are read from the last
`startxref` back through /Prev, newer entries taking precedence.
If the offsets are broken, the objects are found by scanning the file.
"""

import re
from typing import NamedTuple

from . import pdf_filters
from .pdf_lexer import PdfError
from .pdf_parser import Parser

OBJECT_HEADER = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")


class XrefEntry(NamedTuple):
    """Type (0 free, 1 offset, 2 compressed) and its two fields."""

    kind: int
    first: int
    second: int


def find_startxref(data: bytes) -> int:
    """Offset given by the last startxref keyword of the file."""
    position = data.rfind(b"startxref")
    if position < 0:
        raise PdfError("no startxref: this does not look like a PDF")
    parser = Parser(data, position + len(b"startxref"))
    parser.skip_space()
    return int(parser.regular_token())


def _table_row(parser: Parser) -> XrefEntry:
    """One "offset generation n|f" row of a classic table."""
    fields = []
    for _ in range(3):
        parser.skip_space()
        fields.append(parser.regular_token())
    kind = 0
    if fields[2] == b"n":
        kind = 1
    return XrefEntry(kind, int(fields[0]), int(fields[1]))


def _read_table(parser: Parser):
    """Read a classic "xref" table and its trailer dictionary."""
    parser.pos += len(b"xref")
    entries = {}
    while True:
        parser.skip_space()
        if parser.data.startswith(b"trailer", parser.pos):
            parser.pos += len(b"trailer")
            return entries, parser.parse_object()
        first = int(parser.regular_token())
        parser.skip_space()
        count = int(parser.regular_token())
        for number in range(first, first + count):
            entries[number] = _table_row(parser)


def _stream_entries(data: bytes, widths: list, index: list) -> dict:
    """Decode the fixed-width binary rows of a cross-reference stream."""
    entries = {}
    pos = 0
    for pair in range(0, len(index), 2):
        for number in range(index[pair], index[pair] + index[pair + 1]):
            fields = []
            for width in widths:
                fields.append(int.from_bytes(data[pos:pos + width], "big"))
                pos += width
            if widths[0] == 0:
                fields[0] = 1
            entries[number] = XrefEntry(*fields)
    return entries


def _read_section(data: bytes, offset: int):
    """(entries, trailer, kind) of the section at `offset`."""
    parser = Parser(data, offset)
    parser.skip_space()
    if data.startswith(b"xref", parser.pos):
        entries, trailer = _read_table(parser)
        return entries, trailer, "table"
    stream = parser.parse_indirect()[1]
    info = stream.info
    if info.get("Type") != "XRef":
        raise PdfError("startxref does not point to a cross-reference")
    decoded = pdf_filters.decode(stream, _identity)
    index = info.get("Index", [0, info["Size"]])
    return _stream_entries(decoded, info["W"], index), info, "stream"


def _identity(value):
    """Cross-reference stream values are always direct."""
    return value


def _merge(older: dict, newer: dict) -> None:
    """Add entries of an older section that the newer ones do not set."""
    for number, entry in older.items():
        if number not in newer:
            newer[number] = entry


def _follow_chain(data: bytes):
    """Read every section from the last startxref through /Prev."""
    offset = find_startxref(data)
    entries, trailer, kind = _read_section(data, offset)
    seen = {offset}
    section = trailer
    while True:
        if isinstance(section.get("XRefStm"), int):
            _merge(_read_section(data, section["XRefStm"])[0], entries)
        offset = section.get("Prev")
        if not isinstance(offset, int) or offset in seen:
            return entries, trailer, kind
        seen.add(offset)
        older, section, _ = _read_section(data, offset)
        _merge(older, entries)


def _recover(data: bytes):
    """Rebuild the table by scanning for "n g obj" headers."""
    entries = {}
    for match in OBJECT_HEADER.finditer(data):
        entries[int(match.group(1))] = XrefEntry(1, match.start(),
                                                 int(match.group(2)))
    position = data.rfind(b"trailer")
    if position < 0:
        raise PdfError("the PDF structure is damaged beyond repair")
    parser = Parser(data, position + len(b"trailer"))
    return entries, parser.parse_object(), "table"


def read_xref(data: bytes):
    """(entries, newest trailer, "table" or "stream") of the file."""
    try:
        return _follow_chain(data)
    except (PdfError, ValueError, IndexError, KeyError, TypeError):
        return _recover(data)
