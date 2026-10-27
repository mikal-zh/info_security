# PROJECT, 2026
# info_security
# File description:
# Storage and retrieval of personal-data fields under the three ciphers.

"""Personal-data fields, each sealed with AES, DES and RC4."""

from dataclasses import dataclass

from .catalog import FIELDS_BY_NAME
from .crypto import CIPHERS, IntegrityError
from .owner import Owner

UPSERT = """
INSERT INTO personal_data (user_id, field, aes, des, rc4)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (user_id, field) DO UPDATE SET
    aes = excluded.aes, des = excluded.des, rc4 = excluded.rc4,
    updated_at = CURRENT_TIMESTAMP
"""


@dataclass
class FieldValue:
    """A decrypted field with the integrity status of each stored copy."""

    value: str | None
    copies: dict[str, bool]
    consistent: bool
    stored_bytes: dict[str, int]
    preview: dict[str, str]

    @property
    def ok(self) -> bool:
        """True when every copy verified and all copies agree."""
        return self.consistent and all(self.copies.values())


def _save_field(owner: Owner, name: str, value: str) -> None:
    """Seal one field three times, or delete it when the value is empty."""
    if not value:
        owner.conn.execute(
            "DELETE FROM personal_data WHERE user_id = ? AND field = ?",
            (owner.user_id, name))
        return
    context = owner.context(f"field:{name}")
    sealed = []
    for cipher in CIPHERS:
        envelope = owner.keys.seal(cipher, value.encode(), context)
        sealed.append(envelope)
    owner.conn.execute(UPSERT, (owner.user_id, name, *sealed))


def save_personal_data(owner: Owner, values: dict[str, str]) -> None:
    """Store the submitted form; unknown field names are refused."""
    for name, value in values.items():
        if name not in FIELDS_BY_NAME:
            raise ValueError(f"unknown field {name!r}")
        _save_field(owner, name, value)
    owner.conn.commit()


def _open_copies(owner: Owner, row) -> dict[str, str]:
    """Decrypt every copy of a row that passes its HMAC check."""
    context = owner.context(f"field:{row['field']}")
    plain = {}
    for cipher in CIPHERS:
        try:
            sealed = row[cipher.lower()]
            plain[cipher] = owner.keys.open(cipher, sealed, context).decode()
        except (IntegrityError, UnicodeDecodeError):
            continue
    return plain


def _shown_value(plain: dict[str, str]) -> str | None:
    """The value to display: the AES copy, else any valid copy."""
    if "AES" in plain:
        return plain["AES"]
    for value in plain.values():
        return value
    return None


def _field_value(owner: Owner, row) -> FieldValue:
    """Build the FieldValue of one stored row."""
    plain = _open_copies(owner, row)
    copies = {}
    stored_bytes = {}
    preview = {}
    for cipher in CIPHERS:
        sealed = row[cipher.lower()]
        copies[cipher] = cipher in plain
        stored_bytes[cipher] = len(sealed)
        preview[cipher] = sealed[:20].hex()
    different_values = set(plain.values())
    consistent = len(different_values) == 1
    return FieldValue(_shown_value(plain), copies, consistent,
                      stored_bytes, preview)


def load_personal_data(owner: Owner) -> dict[str, FieldValue]:
    """Decrypt all of the owner's fields, keyed by field name."""
    rows = owner.conn.execute(
        "SELECT * FROM personal_data WHERE user_id = ?", (owner.user_id,))
    fields = {}
    for row in rows:
        fields[row["field"]] = _field_value(owner, row)
    return fields
