# PROJECT, 2026
# info_security
# File description:
# Certificate and CMS tests, cross-checked with OpenSSL when available.

"""Certificate and CMS tests, cross-checked with OpenSSL if installed."""

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone

import pytest
from Crypto.PublicKey import RSA

from hrvault.crypto import pkcs1
from hrvault.pdfsign import certificate, certificate_info, cms, cms_reader

CONTENT = b"%PDF-1.7 pretend these are the covered PDF bytes"
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                   reason="openssl is not installed")


@pytest.fixture(scope="module")
def key():
    """One RSA key shared by the tests of this module."""
    return RSA.generate(2048)


@pytest.fixture(scope="module")
def cert(key):
    """A certificate for emp-001 made with that key."""
    return certificate.create(key, "emp-001")


def test_certificate_fields_round_trip(key, cert):
    """Subject, key, validity and self-signature read back correctly."""
    info = certificate_info.parse(cert)
    assert info.subject == "emp-001"
    assert info.public_key == key.public_key().export_key(format="DER")
    assert certificate_info.valid_at(info, datetime.now(timezone.utc))
    assert certificate_info.is_self_signed_by_its_key(info)


def test_detached_cms_round_trip(key, cert):
    """The signed digest, certificate and signature can be read back."""
    digest = hashlib.sha256(CONTENT).digest()
    signed = cms_reader.parse(cms.sign_detached(
        key, cert, digest, datetime.now(timezone.utc)))
    assert signed.message_digest == digest and signed.sha256
    assert signed.certificate.subject == "emp-001"
    pkcs1.verify(key.public_key(), signed.signed_attributes,
                 signed.signature)


def _openssl(tmp_path, *args: str) -> subprocess.CompletedProcess:
    """Run openssl inside tmp_path and capture its output."""
    return subprocess.run(["openssl", *args], cwd=tmp_path,
                          capture_output=True, text=True, check=False)


@needs_openssl
def test_openssl_reads_the_certificate(tmp_path, cert):
    """OpenSSL decodes the certificate and sees the signing key usage."""
    (tmp_path / "cert.der").write_bytes(cert)
    result = _openssl(tmp_path, "x509", "-inform", "DER", "-in", "cert.der",
                      "-noout", "-text")
    assert result.returncode == 0, result.stderr
    assert "Digital Signature, Non Repudiation" in result.stdout
    assert "CN=emp-001" in result.stdout.replace(" = ", "=")


@needs_openssl
def test_openssl_verifies_the_cms_signature(tmp_path, key, cert):
    """OpenSSL accepts the detached signature over the content."""
    digest = hashlib.sha256(CONTENT).digest()
    signed = cms.sign_detached(key, cert, digest, datetime.now(timezone.utc))
    (tmp_path / "sig.der").write_bytes(signed)
    (tmp_path / "content.bin").write_bytes(CONTENT)
    result = _openssl(tmp_path, "cms", "-verify", "-binary", "-inform",
                      "DER", "-in", "sig.der", "-content", "content.bin",
                      "-noverify", "-out", "/dev/null")
    assert result.returncode == 0, result.stderr
    (tmp_path / "content.bin").write_bytes(CONTENT + b"!")
    result = _openssl(tmp_path, "cms", "-verify", "-binary", "-inform",
                      "DER", "-in", "sig.der", "-content", "content.bin",
                      "-noverify", "-out", "/dev/null")
    assert result.returncode != 0
