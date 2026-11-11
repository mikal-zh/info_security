# PROJECT, 2026
# info_security
# File description:
# CMS SignedData (PKCS#7, detached) wrapping a PDF signature.

"""CMS SignedData, detached (RFC 5652), as PDF readers expect it.

A PDF signature of SubFilter ``adbe.pkcs7.detached`` is a DER
ContentInfo holding a SignedData with no content of its own: the signed
content is the PDF bytes outside the signature value. The signature
covers three *signed attributes* rather than the PDF directly:

    contentType   = id-data
    signingTime   = UTCTime of signing
    messageDigest = SHA-256 of the covered PDF bytes

The RSA signature is computed over the DER of those attributes encoded
as a SET (tag 0x31), and they are stored with the implicit tag [0].
"""

from datetime import datetime

from ..crypto import der, pkcs1
from . import certificate_info
from .certificate import algorithm_id, utc_time

ID_DATA = "1.2.840.113549.1.7.1"
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
SHA256 = "2.16.840.1.101.3.4.2.1"
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
CONTENT_TYPE = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
SIGNING_TIME = "1.2.840.113549.1.9.5"


def _attribute(identifier: str, value: bytes) -> bytes:
    """Attribute ::= SEQUENCE { type OID, values SET OF value }."""
    return der.sequence(der.oid(identifier), der.set_of(value))


def signed_attributes(digest: bytes, when: datetime) -> bytes:
    """The signed attributes as a DER SET, the bytes RSA signs."""
    return der.set_of(
        _attribute(CONTENT_TYPE, der.oid(ID_DATA)),
        _attribute(SIGNING_TIME, utc_time(when)),
        _attribute(MESSAGE_DIGEST, der.tlv(der.OCTET_STRING, digest)))


def _signer_info(cert: bytes, attributes: bytes, signature: bytes) -> bytes:
    """SignerInfo identifying the signer by issuer and serial number."""
    info = certificate_info.parse(cert)
    signer_id = der.sequence(info.issuer, info.serial)
    implicit_attributes = b"\xa0" + attributes[1:]
    return der.sequence(
        der.integer(1), signer_id, algorithm_id(SHA256),
        implicit_attributes, algorithm_id(RSA_ENCRYPTION),
        der.tlv(der.OCTET_STRING, signature))


def sign_detached(private_key, cert: bytes, digest: bytes,
                  when: datetime) -> bytes:
    """DER ContentInfo signing a SHA-256 `digest` of detached content."""
    attributes = signed_attributes(digest, when)
    signature = pkcs1.sign(private_key, attributes)
    signed_data = der.sequence(
        der.integer(1), der.set_of(algorithm_id(SHA256)),
        der.sequence(der.oid(ID_DATA)), der.tlv(0xA0, cert),
        der.set_of(_signer_info(cert, attributes, signature)))
    return der.sequence(der.oid(ID_SIGNED_DATA),
                        der.tlv(0xA0, signed_data))
