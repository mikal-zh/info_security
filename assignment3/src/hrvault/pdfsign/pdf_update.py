# PROJECT, 2026
# info_security
# File description:
# Incremental update: append new object versions after the original PDF.

"""Incremental update (ISO 32000-1, section 7.5.6).

New or changed objects are appended after the original bytes, followed
by a cross-reference section for them and a trailer whose /Prev points
to the previous cross-reference. The original bytes are never modified,
which keeps earlier signatures valid. The new section uses the same
form (table or stream) as the newest section of the original file.
"""

from . import pdf_writer
from .pdf_document import PdfDocument
from .pdf_lexer import Name, Ref
from .pdf_xref import find_startxref

KEPT_TRAILER_KEYS = ("Root", "Info", "ID")
XREF_WIDTHS = [1, 4, 2]


def _groups(numbers: list[int]) -> list[list[int]]:
    """Split sorted object numbers into runs of consecutive numbers."""
    groups = []
    for object_number in numbers:
        if groups and groups[-1][-1] + 1 == object_number:
            groups[-1].append(object_number)
        else:
            groups.append([object_number])
    return groups


class IncrementalUpdate:
    """Collects new object versions and writes them after the file."""

    def __init__(self, document: PdfDocument):
        """Start an empty update of `document`."""
        self.document = document
        self.objects = {}
        self.next_number = document.size()

    def new_ref(self) -> Ref:
        """Reserve the number of a new object."""
        ref = Ref(self.next_number, 0)
        self.next_number += 1
        return ref

    def put(self, ref: Ref, body: bytes) -> None:
        """Add or replace object `ref` with already serialised `body`."""
        self.objects[ref.number] = (ref.generation, body)

    def _trailer(self) -> dict:
        """Trailer entries: size, previous xref, root, info and ID."""
        trailer = {"Size": self.next_number,
                   "Prev": find_startxref(self.document.data)}
        for key in KEPT_TRAILER_KEYS:
            if key in self.document.trailer:
                trailer[key] = self.document.trailer[key]
        return trailer

    def _write_objects(self, output: bytearray) -> dict:
        """Append every object; return {number: (offset, generation)}."""
        offsets = {}
        for object_number in sorted(self.objects):
            generation, body = self.objects[object_number]
            offsets[object_number] = (len(output), generation)
            header = f"{object_number} {generation} obj\n".encode()
            output += header + body + b"\nendobj\n"
        return offsets

    def _xref_table(self, output: bytearray, offsets: dict) -> None:
        """Append a classic xref table, the trailer and startxref."""
        start = len(output)
        output += b"xref\n"
        for group in _groups(sorted(offsets)):
            output += f"{group[0]} {len(group)}\n".encode()
            for object_number in group:
                offset, generation = offsets[object_number]
                output += f"{offset:010d} {generation:05d} n\r\n".encode()
        output += b"trailer\n" + pdf_writer.serialize(self._trailer())
        output += f"\nstartxref\n{start}\n%%EOF\n".encode()

    def _xref_stream(self, output: bytearray, offsets: dict) -> None:
        """Append a cross-reference stream object and startxref."""
        ref = self.new_ref()
        offsets[ref.number] = (len(output), 0)
        index = []
        rows = b""
        for group in _groups(sorted(offsets)):
            index += [group[0], len(group)]
            for object_number in group:
                offset, generation = offsets[object_number]
                rows += b"\x01" + offset.to_bytes(4, "big")
                rows += generation.to_bytes(2, "big")
        info = self._trailer()
        info.update({"Type": Name("XRef"), "W": XREF_WIDTHS, "Index": index,
                     "Length": len(rows)})
        output += f"{ref.number} 0 obj\n".encode()
        output += pdf_writer.serialize(info) + b"\nstream\n" + rows
        start = offsets[ref.number][0]
        output += f"\nendstream\nendobj\nstartxref\n{start}\n%%EOF\n".encode()

    def build(self) -> bytearray:
        """The original bytes followed by the update."""
        output = bytearray(self.document.data)
        if not output.endswith(b"\n"):
            output += b"\n"
        offsets = self._write_objects(output)
        if self.document.xref_kind == "stream":
            self._xref_stream(output, offsets)
        else:
            self._xref_table(output, offsets)
        return output
