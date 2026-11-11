# PROJECT, 2026
# info_security
# File description:
# Stream decoding: FlateDecode with optional PNG predictors.

"""Stream decoding: FlateDecode with optional PNG predictors.

Cross-reference streams and object streams are almost always Flate
compressed, often with the PNG "Up" predictor. Only what is needed to
read those structures is supported.
"""

import zlib

from .pdf_lexer import Name, PdfError, Stream


def _paeth(left: int, up: int, up_left: int) -> int:
    """PNG Paeth predictor: the neighbour closest to left + up - upleft."""
    estimate = left + up - up_left
    distance_left = abs(estimate - left)
    distance_up = abs(estimate - up)
    distance_up_left = abs(estimate - up_left)
    if distance_left <= distance_up and distance_left <= distance_up_left:
        return left
    if distance_up <= distance_up_left:
        return up
    return up_left


def _unfilter_row(kind: int, row: bytearray, previous: bytes,
                  step: int) -> None:
    """Undo one PNG row filter in place (step = bytes per pixel)."""
    for index in range(len(row)):
        left = 0
        up_left = 0
        if index >= step:
            left = row[index - step]
            up_left = previous[index - step]
        up = previous[index]
        prediction = 0
        if kind == 1:
            prediction = left
        elif kind == 2:
            prediction = up
        elif kind == 3:
            prediction = (left + up) // 2
        elif kind == 4:
            prediction = _paeth(left, up, up_left)
        row[index] = (row[index] + prediction) & 0xFF


def png_unpredict(data: bytes, params: dict) -> bytes:
    """Reverse PNG predictors (Predictor >= 10) row by row."""
    colors = params.get("Colors", 1)
    bits = params.get("BitsPerComponent", 8)
    width = (params.get("Columns", 1) * colors * bits + 7) // 8
    step = max(1, colors * bits // 8)
    previous = bytes(width)
    output = bytearray()
    for start in range(0, len(data) - width, width + 1):
        row = bytearray(data[start + 1:start + 1 + width])
        _unfilter_row(data[start], row, previous, step)
        output += row
        previous = bytes(row)
    return bytes(output)


def decode(stream: Stream, resolve) -> bytes:
    """Decoded bytes of a stream; PdfError for unsupported filters."""
    filters = resolve(stream.info.get("Filter"))
    params = resolve(stream.info.get("DecodeParms"))
    if filters is None:
        return stream.raw
    if isinstance(filters, Name):
        filters = [filters]
    if isinstance(params, list):
        params = params[0]
    if filters != ["FlateDecode"]:
        raise PdfError(f"unsupported stream filter {filters}")
    data = zlib.decompressobj().decompress(stream.raw)
    if isinstance(params, dict) and params.get("Predictor", 1) >= 10:
        data = png_unpredict(data, params)
    return data
