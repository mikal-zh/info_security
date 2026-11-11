# PROJECT, 2026
# info_security
# File description:
# Parser for PDF objects: dictionaries, arrays, references and streams.

"""Parser for PDF objects, including "n g obj ... endobj" objects."""

from .pdf_lexer import (DELIMITERS, WHITESPACE, Lexer, Name, PdfError, Ref,
                        Stream)

KEYWORDS = {b"true": True, b"false": False, b"null": None}


def number(token: bytes) -> int | float:
    """Convert a numeric token; PdfError if it is not a number."""
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError as exc:
        raise PdfError(f"unexpected token {token[:20]!r}") from exc


class Parser(Lexer):
    """Builds Python values from PDF object syntax."""

    def parse_object(self):
        """Read the next object."""
        self.skip_space()
        if self.pos >= len(self.data):
            raise PdfError("unexpected end of file")
        byte = self.data[self.pos]
        if byte == ord("/"):
            return self.name()
        if byte == ord("("):
            return self.literal_string()
        if self.data.startswith(b"<<", self.pos):
            return self._dictionary()
        if byte == ord("<"):
            return self.hex_string()
        if byte == ord("["):
            return self._array()
        return self._keyword_or_number()

    def _keyword_or_number(self):
        """Read true, false, null, a number or a reference."""
        token = self.regular_token()
        if token in KEYWORDS:
            return KEYWORDS[token]
        if not token:
            raise PdfError(f"unexpected byte at offset {self.pos}")
        return self._number_or_reference(number(token))

    def _number_or_reference(self, value):
        """Return Ref(value, gen) for "value gen R", else the number."""
        saved = self.pos
        if not isinstance(value, int):
            return value
        self.skip_space()
        generation = self.regular_token()
        self.skip_space()
        after = self.data[self.pos + 1:self.pos + 2]
        is_end = after == b"" or after in WHITESPACE or after in DELIMITERS
        if (generation.isdigit() and self.data[self.pos:self.pos + 1] == b"R"
                and is_end):
            self.pos += 1
            return Ref(value, int(generation))
        self.pos = saved
        return value

    def _dictionary(self) -> dict:
        """Read << /Key value ... >>."""
        self.pos += 2
        result = {}
        while True:
            self.skip_space()
            if self.data.startswith(b">>", self.pos):
                self.pos += 2
                return result
            key = self.parse_object()
            if not isinstance(key, Name):
                raise PdfError("dictionary key is not a name")
            result[key] = self.parse_object()

    def _array(self) -> list:
        """Read [ item ... ]."""
        self.pos += 1
        items = []
        while True:
            self.skip_space()
            if self.data[self.pos:self.pos + 1] == b"]":
                self.pos += 1
                return items
            items.append(self.parse_object())

    def parse_indirect(self, length_of=None):
        """Read "n g obj value [stream] endobj"; return (Ref, value).

        `length_of` resolves a stream /Length given as a reference.
        """
        self.skip_space()
        object_number = int(self.regular_token())
        self.skip_space()
        generation = int(self.regular_token())
        self.skip_space()
        if self.regular_token() != b"obj":
            raise PdfError(f"no object at offset {self.pos}")
        value = self.parse_object()
        self.skip_space()
        if self.data.startswith(b"stream", self.pos):
            value = Stream(value, self._stream_data(value, length_of))
        return Ref(object_number, generation), value

    def _stream_data(self, info: dict, length_of) -> bytes:
        """Raw stream bytes, using /Length and checking for endstream."""
        self.pos += len(b"stream")
        if self.data[self.pos:self.pos + 2] == b"\r\n":
            self.pos += 1
        self.pos += 1
        start = self.pos
        length = info.get("Length")
        if isinstance(length, Ref) and length_of is not None:
            length = length_of(length)
        end = self._stream_end(start, length)
        self.pos = end
        return self.data[start:end]

    def _stream_end(self, start: int, length) -> int:
        """End of the stream data: start + /Length if it checks out.

        A wrong or missing /Length falls back to the next endstream.
        """
        if isinstance(length, int):
            end = start + length
            tail = self.data[end:end + 12].lstrip(WHITESPACE)
            if tail.startswith(b"endstream"):
                return end
        end = self.data.find(b"endstream", start)
        if end < 0:
            raise PdfError("stream without endstream")
        return end
