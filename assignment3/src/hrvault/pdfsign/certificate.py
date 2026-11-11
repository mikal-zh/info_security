# PROJECT, 2026
# info_security
# File description:
# Self-signed X.509 v3 certificate binding a user's name to their key.

"""Self-signed X.509 v3 certificates (RFC 5280), built by hand in DER.

A PDF reader needs a certificate, not a bare public key, to check a
signature. Each user's certificate names them (CN = employee number,
O = Onboarding Vault), carries their RSA public key and is signed with
their own private key:

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
                               signatureValue BIT STRING }

Key usage is limited to digitalSignature and nonRepudiation, which is
what document signing needs.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from ..crypto import der, pkcs1

SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
COMMON_NAME = "2.5.4.3"
ORGANIZATION = "2.5.4.10"
BASIC_CONSTRAINTS = "2.5.29.19"
KEY_USAGE = "2.5.29.15"
SUBJECT_KEY_ID = "2.5.29.14"
ORGANIZATION_NAME = "Onboarding Vault"
VALIDITY = timedelta(days=730)
CLOCK_SKEW = timedelta(minutes=5)
SIGNING_KEY_USAGE = bytes([6, 0xC0])
BOOLEAN_TRUE = bytes([0x01, 0x01, 0xFF])


def algorithm_id(identifier: str) -> bytes:
    """AlgorithmIdentifier with NULL parameters."""
    return der.sequence(der.oid(identifier), der.tlv(der.NULL, b""))


def name(common_name: str) -> bytes:
    """Distinguished name O=Onboarding Vault, CN=<common_name>."""
    organization = der.sequence(
        der.oid(ORGANIZATION),
        der.tlv(der.UTF8_STRING, ORGANIZATION_NAME.encode()))
    person = der.sequence(der.oid(COMMON_NAME),
                          der.tlv(der.UTF8_STRING, common_name.encode()))
    return der.sequence(der.set_of(organization), der.set_of(person))


def utc_time(moment: datetime) -> bytes:
    """UTCTime YYMMDDHHMMSSZ (valid for years up to 2049)."""
    text = moment.astimezone(timezone.utc).strftime("%y%m%d%H%M%SZ")
    return der.tlv(der.UTC_TIME, text.encode())


def _extension(identifier: str, value: bytes, critical: bool) -> bytes:
    """One Extension: OID, optional critical flag, DER value."""
    parts = der.oid(identifier)
    if critical:
        parts += BOOLEAN_TRUE
    parts += der.tlv(der.OCTET_STRING, value)
    return der.tlv(der.SEQUENCE, parts)


def _extensions(public_key: bytes) -> bytes:
    """[3] extensions: not a CA, signing-only key usage, key id."""
    key_id = hashlib.sha1(public_key).digest()
    items = der.sequence(
        _extension(BASIC_CONSTRAINTS, der.sequence(), True),
        _extension(KEY_USAGE, der.tlv(der.BIT_STRING, SIGNING_KEY_USAGE),
                   True),
        _extension(SUBJECT_KEY_ID, der.tlv(der.OCTET_STRING, key_id),
                   False))
    return der.tlv(0xA3, items)


def _to_be_signed(private_key, common_name: str, now: datetime) -> bytes:
    """The TBSCertificate: version 3, random serial, issuer = subject."""
    serial = secrets.randbits(63) | 1
    validity = der.sequence(utc_time(now - CLOCK_SKEW),
                            utc_time(now + VALIDITY))
    public_key = private_key.public_key().export_key(format="DER")
    subject = name(common_name)
    return der.sequence(
        der.tlv(0xA0, der.integer(2)), der.integer(serial),
        algorithm_id(SHA256_WITH_RSA), subject, validity, subject,
        public_key, _extensions(public_key))


def create(private_key, common_name: str) -> bytes:
    """A DER certificate for the key's owner, signed with that key."""
    now = datetime.now(timezone.utc)
    to_be_signed = _to_be_signed(private_key, common_name, now)
    signature = pkcs1.sign(private_key, to_be_signed)
    return der.sequence(to_be_signed, algorithm_id(SHA256_WITH_RSA),
                        der.tlv(der.BIT_STRING, b"\x00" + signature))
