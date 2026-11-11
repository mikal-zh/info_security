# PROJECT, 2026
# info_security
# File description:
# Small one-page PDFs built by hand, in the two cross-reference styles.

"""Small one-page PDFs built by hand, in both cross-reference styles.

`classic_pdf` uses an xref table (PDF 1.4 style). `compressed_pdf` puts
most objects in a Flate-compressed object stream and indexes them with a
cross-reference stream using the PNG Up predictor (PDF 1.5 style).
"""

import zlib
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"


def _bodies(text: str) -> dict[int, bytes]:
    """Catalog, page tree, page, content stream and font objects."""
    content = f"BT /F1 18 Tf 72 760 Td ({text}) Tj ET".encode()
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]"
           b" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        4: b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
           + content + b"\nendstream",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }


def _object(number: int, body: bytes) -> bytes:
    """One "n 0 obj ... endobj" block."""
    return f"{number} 0 obj\n".encode() + body + b"\nendobj\n"


def classic_pdf(text: str = "Employment contract") -> bytes:
    """A PDF with a classic cross-reference table."""
    output = HEADER
    offsets = []
    for number, body in _bodies(text).items():
        offsets.append(len(output))
        output += _object(number, body)
    start = len(output)
    output += b"xref\n0 6\n0000000000 65535 f\r\n"
    for offset in offsets:
        output += f"{offset:010d} 00000 n\r\n".encode()
    output += b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
    return output + f"startxref\n{start}\n%%EOF\n".encode()


def _png_up(rows: list[bytes]) -> bytes:
    """Encode equal-length rows with the PNG Up filter (type 2)."""
    previous = bytes(len(rows[0]))
    encoded = b""
    for row in rows:
        delta = bytearray()
        for index, byte in enumerate(row):
            delta.append((byte - previous[index]) & 0xFF)
        encoded += b"\x02" + bytes(delta)
        previous = row
    return encoded


def _object_stream(bodies: dict, numbers: list[int]) -> bytes:
    """Object 6: an object stream holding the listed objects."""
    header = b""
    data = b""
    for number in numbers:
        header += f"{number} {len(data)} ".encode()
        data += bodies[number] + b" "
    packed = zlib.compress(header + data)
    info = (f"<< /Type /ObjStm /N {len(numbers)} /First {len(header)}"
            f" /Filter /FlateDecode /Length {len(packed)} >>")
    return info.encode() + b"\nstream\n" + packed + b"\nendstream"


def _xref_rows(offsets: dict, numbers: list[int]) -> list[bytes]:
    """Rows of [type, field 2 (2 bytes), field 3] for objects 0 to 7."""
    rows = [b"\x00\x00\x00\xff"]
    for number in range(1, 8):
        if number in numbers:
            rows.append(b"\x02\x00\x06" + bytes([numbers.index(number)]))
        else:
            rows.append(b"\x01" + offsets[number].to_bytes(2, "big")
                        + b"\x00")
    return rows


def compressed_pdf(text: str = "Employment contract") -> bytes:
    """A PDF using an object stream and a predicted xref stream."""
    bodies = _bodies(text)
    numbers = [1, 2, 3, 5]
    output = HEADER
    offsets = {4: len(output)}
    output += _object(4, bodies[4])
    offsets[6] = len(output)
    output += _object(6, _object_stream(bodies, numbers))
    offsets[7] = len(output)
    packed = zlib.compress(_png_up(_xref_rows(offsets, numbers)))
    info = (f"<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R"
            " /Filter /FlateDecode /DecodeParms << /Predictor 12"
            f" /Columns 4 >> /Length {len(packed)} >>")
    output += _object(7, info.encode() + b"\nstream\n" + packed
                      + b"\nendstream")
    return output + f"startxref\n{offsets[7]}\n%%EOF\n".encode()


def fixture(name: str) -> bytes:
    """A real-world PDF from tests/fixtures (LibreOffice, Ghostscript)."""
    return (FIXTURES / name).read_bytes()
