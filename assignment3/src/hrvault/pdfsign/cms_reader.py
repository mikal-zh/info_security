# PROJECT, 2026
# info_security
# File description:
# Decoding a detached CMS SignedData found in a PDF signature.

"""Decoding a detached CMS SignedData found in a PDF signature.

Extracts the signer's certificate, the signed attributes (re-encoded as
a SET, the form the signature covers), the message digest, the signing
time and the RSA signature value.
"""

from datetime import datetime
from typing import NamedTuple

from ..crypto import der
from . import certificate_info
from .cms import ID_SIGNED_DATA, MESSAGE_DIGEST, SHA256, SIGNING_TIME


class SignedMessage(NamedTuple):
    """The parts of a SignedData needed to check it."""

    certificate: certificate_info.Certificate
    signed_attributes: bytes
    message_digest: bytes
    signing_time: datetime | None
    signature: bytes
    sha256: bool


def _attribute_values(attributes: der.Tlv) -> dict[bytes, der.Tlv]:
    """Map each attribute OID (DER) to its first value."""
    values = {}
    for attribute in der.children(attributes.content):
        parts = der.children(attribute.content)
        values[parts[0].encoded] = der.children(parts[1].content)[0]
    return values


def _signer_certificate(fields: list, serial: bytes):
    """The certificate whose serial number matches the signer's."""
    certificates = []
    for field in fields:
        if field.tag == 0xA0:
            certificates = der.children(field.content)
    for item in certificates:
        cert = certificate_info.parse(item.encoded)
        if cert.serial == serial:
            return cert
    raise ValueError("signer certificate not found in the signature")


def _signing_time(values: dict) -> datetime | None:
    """The signingTime attribute, if present."""
    item = values.get(der.oid(SIGNING_TIME))
    if item is None:
        return None
    return certificate_info.decode_time(item)


def parse(encoded: bytes) -> SignedMessage:
    """Decode a ContentInfo; ValueError if it is not usable SignedData."""
    content_info = der.children(der.read(encoded).content)
    if content_info[0].encoded != der.oid(ID_SIGNED_DATA):
        raise ValueError("not a CMS SignedData")
    signed_data = der.read(content_info[1].content)
    fields = der.children(signed_data.content)
    signer = der.children(der.children(fields[-1].content)[0].content)
    attributes = signer[3]
    if attributes.tag != 0xA0:
        raise ValueError("signature has no signed attributes")
    values = _attribute_values(attributes)
    issuer_serial = der.children(signer[1].content)
    return SignedMessage(
        certificate=_signer_certificate(fields, issuer_serial[1].encoded),
        signed_attributes=b"\x31" + attributes.encoded[1:],
        message_digest=values[der.oid(MESSAGE_DIGEST)].content,
        signing_time=_signing_time(values), signature=signer[5].content,
        sha256=der.children(signer[2].content)[0].encoded == der.oid(SHA256))
