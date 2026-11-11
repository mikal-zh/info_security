# PROJECT, 2026
# info_security
# File description:
# Random access to the objects of a PDF file.

"""Random access to the objects of a PDF file.

Objects are looked up through the cross-reference and parsed on demand,
either at their byte offset or inside a compressed object stream.
"""

from . import pdf_filters, pdf_xref
from .pdf_lexer import PdfError, Ref
from .pdf_parser import Parser


class PdfDocument:
    """A parsed PDF: its cross-reference, trailer and objects."""

    def __init__(self, data: bytes):
        """Read the cross-reference; PdfError for encrypted files."""
        if not data.lstrip()[:5] == b"%PDF-":
            raise PdfError("this file does not start with %PDF-")
        self.data = data
        self.entries, self.trailer, self.xref_kind = pdf_xref.read_xref(data)
        if "Encrypt" in self.trailer:
            raise PdfError("password-protected PDFs cannot be signed")
        self._cache = {}

    def get(self, number: int):
        """The object with this number, or None if it does not exist."""
        if number in self._cache:
            return self._cache[number]
        entry = self.entries.get(number)
        value = None
        if entry is not None and entry.kind == 1:
            parser = Parser(self.data, entry.first)
            value = parser.parse_indirect(self._length)[1]
        elif entry is not None and entry.kind == 2:
            value = self._compressed(entry.first, entry.second)
        self._cache[number] = value
        return value

    def _length(self, ref: Ref) -> int:
        """Resolve a stream /Length given as an indirect reference."""
        return self.get(ref.number)

    def resolve(self, value):
        """Follow indirect references until a direct value is reached."""
        while isinstance(value, Ref):
            value = self.get(value.number)
        return value

    def _compressed(self, stream_number: int, index: int):
        """Object number `index` of the object stream `stream_number`."""
        stream = self.get(stream_number)
        data = pdf_filters.decode(stream, self.resolve)
        parser = Parser(data)
        offsets = []
        for _ in range(self.resolve(stream.info["N"])):
            parser.parse_object()
            offsets.append(parser.parse_object())
        first = self.resolve(stream.info["First"])
        return Parser(data, first + offsets[index]).parse_object()

    def catalog(self) -> dict:
        """The document catalog (/Root)."""
        catalog = self.resolve(self.trailer.get("Root"))
        if not isinstance(catalog, dict):
            raise PdfError("the PDF has no document catalog")
        return catalog

    def first_page(self) -> tuple[Ref, dict]:
        """Reference and dictionary of the first page."""
        node_ref = self.catalog().get("Pages")
        for _ in range(64):
            node = self.resolve(node_ref)
            if not isinstance(node, dict) or not isinstance(node_ref, Ref):
                break
            kids = self.resolve(node.get("Kids"))
            if node.get("Type") == "Page" or not kids:
                return node_ref, node
            node_ref = kids[0]
        raise PdfError("the PDF has no page")

    def size(self) -> int:
        """First object number free for new objects."""
        size = self.trailer.get("Size", 0)
        for number in self.entries:
            size = max(size, number + 1)
        return size
