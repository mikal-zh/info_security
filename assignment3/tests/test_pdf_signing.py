# PROJECT, 2026
# info_security
# File description:
# Signing tests: embed, verify, tamper, sign twice, third-party reader.

"""Signing tests: embed, verify, tamper, sign twice, third-party reader."""

import shutil
import subprocess

import pytest
from Crypto.PublicKey import RSA

from hrvault.pdfsign import certificate, signer, verifier
from tests.sample_pdfs import classic_pdf, compressed_pdf, fixture

SOURCES = ["classic", "compressed", "libreoffice.pdf", "ghostscript.pdf"]


def _load(source: str) -> bytes:
    """A hand-built sample PDF or a real-world fixture file."""
    if source == "classic":
        return classic_pdf()
    if source == "compressed":
        return compressed_pdf()
    return fixture(source)


@pytest.fixture(scope="module")
def emp_signer():
    """A signer for emp-001 with a 2048-bit key and its certificate."""
    key = RSA.generate(2048)
    return signer.Signer(key, certificate.create(key, "emp-001"), "emp-001",
                         "Approved")


@pytest.mark.parametrize("source", SOURCES)
def test_signed_pdf_verifies(emp_signer, source):
    """Every kind of PDF gets one valid signature covering it all."""
    original = _load(source)
    signed = signer.sign_pdf(original, emp_signer)
    assert signed.startswith(original)
    checks = verifier.verify_pdf(signed)
    assert len(checks) == 1
    assert checks[0].valid and checks[0].whole_file
    assert checks[0].certificate_ok and checks[0].signer == "emp-001"


def test_change_after_signing_is_detected(emp_signer):
    """Changing one covered byte breaks the digest check."""
    signed = bytearray(signer.sign_pdf(classic_pdf(), emp_signer))
    position = signed.find(b"Employment")
    signed[position] = ord("X")
    check = verifier.verify_pdf(bytes(signed))[0]
    assert not check.valid and not check.intact
    assert "the document changed after signing" in check.problems


def test_second_signature_keeps_the_first(emp_signer):
    """Signing twice: both verify, only the last covers the whole file."""
    once = signer.sign_pdf(compressed_pdf(), emp_signer)
    twice = signer.sign_pdf(once, emp_signer)
    first, second = verifier.verify_pdf(twice)
    assert first.valid and not first.whole_file
    assert second.valid and second.whole_file


def test_unsigned_pdf_has_no_signature():
    """A PDF without signature fields reports nothing."""
    assert verifier.verify_pdf(classic_pdf()) == []


@pytest.mark.skipif(shutil.which("pdfsig") is None,
                    reason="poppler's pdfsig is not installed")
@pytest.mark.parametrize("source", SOURCES)
def test_third_party_reader_accepts_the_signature(tmp_path, emp_signer,
                                                  source):
    """Poppler (used by many PDF viewers) validates the signature."""
    path = tmp_path / "signed.pdf"
    path.write_bytes(signer.sign_pdf(_load(source), emp_signer))
    result = subprocess.run(["pdfsig", str(path)], capture_output=True,
                            text=True, check=False)
    assert "Signature Validation: Signature is Valid." in result.stdout
    assert "Total document signed" in result.stdout
