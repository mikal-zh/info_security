# PROJECT, 2026
# info_security
# File description:
# Reading the fields of a DER X.509 certificate.

"""Reading the fields of a DER X.509 certificate.

Only the fields a signature check needs are extracted: serial and
issuer (to match the CMS signer), subject common name, public key,
validity period and the certificate's own signature.
"""

from datetime import datetime, timezone
from typing import NamedTuple

from Crypto.PublicKey import RSA

from ..crypto import der, pkcs1
from .certificate import COMMON_NAME

GENERALIZED_TIME = 0x18


class Certificate(NamedTuple):
    """The decoded parts of a certificate."""

    encoded: bytes
    to_be_signed: bytes
    serial: bytes
    issuer: bytes
    subject: str
    public_key: bytes
    not_before: datetime
    not_after: datetime
    signature: bytes


def _common_name(name_tlv: der.Tlv) -> str:
    """The CN of a distinguished name, or "" if it has none."""
    wanted = der.oid(COMMON_NAME)
    for relative in der.children(name_tlv.content):
        for attribute in der.children(relative.content):
            parts = der.children(attribute.content)
            if parts[0].encoded == wanted:
                return parts[1].content.decode("utf-8", "replace")
    return ""


def decode_time(item: der.Tlv) -> datetime:
    """Decode a UTCTime or GeneralizedTime value."""
    text = item.content.decode()
    pattern = "%y%m%d%H%M%SZ"
    if item.tag == GENERALIZED_TIME:
        pattern = "%Y%m%d%H%M%SZ"
    moment = datetime.strptime(text, pattern)
    return moment.replace(tzinfo=timezone.utc)


def parse(encoded: bytes) -> Certificate:
    """Decode a DER certificate; ValueError if it is malformed."""
    top = der.children(der.read(encoded).content)
    to_be_signed, signature = top[0], top[2]
    fields = der.children(to_be_signed.content)
    if fields[0].tag == 0xA0:
        fields = fields[1:]
    validity = der.children(fields[3].content)
    return Certificate(
        encoded=der.read(encoded).encoded,
        to_be_signed=to_be_signed.encoded, serial=fields[0].encoded,
        issuer=fields[2].encoded, subject=_common_name(fields[4]),
        public_key=fields[5].encoded, not_before=decode_time(validity[0]),
        not_after=decode_time(validity[1]), signature=signature.content[1:])


def public_key(cert: Certificate):
    """The certificate's RSA public key as a key object."""
    return RSA.import_key(cert.public_key)


def is_self_signed_by_its_key(cert: Certificate) -> bool:
    """True if the certificate's signature verifies with its own key."""
    try:
        pkcs1.verify(public_key(cert), cert.to_be_signed, cert.signature)
    except (pkcs1.SignatureError, ValueError):
        return False
    return True


def valid_at(cert: Certificate, moment: datetime) -> bool:
    """True if `moment` falls inside the certificate's validity period."""
    return cert.not_before <= moment <= cert.not_after
