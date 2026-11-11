# PROJECT, 2026
# info_security
# File description:
# PDF reader tests: lexer, parser, both xref styles and recovery.

"""PDF reader tests: lexer, parser, both xref styles and recovery."""

import pytest

from hrvault.pdfsign.pdf_document import PdfDocument
from hrvault.pdfsign.pdf_lexer import Name, PdfError, Ref
from hrvault.pdfsign.pdf_parser import Parser
from hrvault.pdfsign.pdf_writer import serialize
from tests.sample_pdfs import classic_pdf, compressed_pdf, fixture


@pytest.mark.parametrize("source, expected", [
    (b"(a\\(b\\)c (nested) \\101)", b"a(b)c (nested) A"),
    (b"<48656C6C6F2>", b"Hello "),
    (b"/A#20B", Name("A B")),
    (b"[1 2 R 3 4.5 true null]", [Ref(1, 2), 3, 4.5, True, None]),
    (b"<< /K [1 2] % comment\n /V (x) >>", {"K": [1, 2], "V": b"x"}),
])
def test_parser_reads_pdf_syntax(source, expected):
    """Strings, names, references, numbers and dictionaries."""
    assert Parser(source).parse_object() == expected


def test_writer_output_parses_back():
    """serialize() and the parser agree with each other."""
    value = {"Name": Name("A B"), "List": [Ref(4, 0), -1.5, b"\x00)("],
             "Flag": False, "Empty": None}
    assert Parser(serialize(value)).parse_object() == value


@pytest.mark.parametrize("build, kind", [
    (classic_pdf, "table"), (compressed_pdf, "stream"),
])
def test_both_cross_reference_styles(build, kind):
    """Objects are found by offset and inside object streams."""
    document = PdfDocument(build())
    assert document.xref_kind == kind
    page_ref, page = document.first_page()
    assert page_ref == Ref(3, 0) and page["Type"] == "Page"
    assert document.catalog()["Type"] == "Catalog"


@pytest.mark.parametrize("name", ["libreoffice.pdf", "ghostscript.pdf"])
def test_real_world_files(name):
    """PDFs made by LibreOffice and Ghostscript are understood."""
    page = PdfDocument(fixture(name)).first_page()[1]
    assert page["Type"] == "Page"


def test_broken_offsets_are_recovered():
    """A wrong startxref falls back to scanning the objects."""
    data = classic_pdf().replace(b"startxref\n", b"startxref\n1")
    assert PdfDocument(data).first_page()[0] == Ref(3, 0)


@pytest.mark.parametrize("data", [
    b"not a pdf at all",
    classic_pdf().replace(b"/Root 1 0 R", b"/Root 1 0 R /Encrypt 9 0 R"),
])
def test_unusable_files_are_refused(data):
    """Non-PDF and password-protected files raise PdfError."""
    with pytest.raises(PdfError):
        PdfDocument(data)
