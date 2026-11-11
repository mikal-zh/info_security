# PROJECT, 2026
# info_security
# File description:
# PDF object types and the lexer for names, strings and tokens.

"""PDF object types and lexer (ISO 32000-1, sections 7.2 and 7.3).

Python values stand for PDF objects: dict, list, int, float, bool,
None, bytes (strings), `Name`, `Ref` (indirect reference) and `Stream`.
"""

from dataclasses import dataclass
from typing import NamedTuple

WHITESPACE = b"\x00\t\n\x0c\r "
DELIMITERS = b"()<>[]{}/%"
ESCAPES = {
    ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b",
    ord("f"): b"\f", ord("("): b"(", ord(")"): b")", ord("\\"): b"\\",
}


class PdfError(Exception):
    """The file is not a PDF this module can read or sign."""


class Name(str):
    """A PDF name such as /Type, stored without its slash."""


class Ref(NamedTuple):
    """An indirect reference "number generation R"."""

    number: int
    generation: int


@dataclass
class Stream:
    """A stream object: its dictionary and its raw (encoded) bytes."""

    info: dict
    raw: bytes


class Lexer:
    """Reads tokens from PDF bytes, starting at a position."""

    def __init__(self, data: bytes, pos: int = 0):
        """Read `data` from offset `pos`."""
        self.data = data
        self.pos = pos

    def skip_space(self) -> None:
        """Skip whitespace and % comments."""
        while self.pos < len(self.data):
            byte = self.data[self.pos]
            if byte == ord("%"):
                while (self.pos < len(self.data)
                       and self.data[self.pos] not in b"\r\n"):
                    self.pos += 1
            elif byte in WHITESPACE:
                self.pos += 1
            else:
                return

    def regular_token(self) -> bytes:
        """Read a run of regular characters (keyword or number)."""
        start = self.pos
        while (self.pos < len(self.data)
               and self.data[self.pos] not in WHITESPACE
               and self.data[self.pos] not in DELIMITERS):
            self.pos += 1
        return self.data[start:self.pos]

    def name(self) -> Name:
        """Read a /Name, decoding #xx escapes."""
        self.pos += 1
        raw = self.regular_token()
        text = bytearray()
        index = 0
        while index < len(raw):
            if raw[index] == ord("#") and index + 2 < len(raw):
                text += bytes.fromhex(raw[index + 1:index + 3].decode())
                index += 3
            else:
                text.append(raw[index])
                index += 1
        return Name(text.decode("latin-1"))

    def hex_string(self) -> bytes:
        """Read a <hex> string; an odd final digit counts as d0."""
        end = self.data.index(b">", self.pos)
        digits = bytes(self.data[self.pos + 1:end]).translate(None,
                                                              WHITESPACE)
        self.pos = end + 1
        if len(digits) % 2:
            digits += b"0"
        return bytes.fromhex(digits.decode("ascii"))

    def literal_string(self) -> bytes:
        """Read a (literal) string with nested parentheses and escapes."""
        self.pos += 1
        depth = 1
        text = bytearray()
        while True:
            byte = self.data[self.pos]
            self.pos += 1
            if byte == ord("\\"):
                text += self._escape()
                continue
            if byte == ord("("):
                depth += 1
            elif byte == ord(")"):
                depth -= 1
                if depth == 0:
                    return bytes(text)
            text.append(byte)

    def _escape(self) -> bytes:
        """Decode the character after a backslash in a literal string."""
        byte = self.data[self.pos]
        if byte in ESCAPES:
            self.pos += 1
            return ESCAPES[byte]
        if byte in b"\r\n":
            if self.data[self.pos:self.pos + 2] == b"\r\n":
                self.pos += 1
            self.pos += 1
            return b""
        digits = b""
        while len(digits) < 3 and self.data[self.pos] in b"01234567":
            digits += self.data[self.pos:self.pos + 1]
            self.pos += 1
        if digits:
            return bytes([int(digits, 8) & 0xFF])
        self.pos += 1
        return bytes([byte])
