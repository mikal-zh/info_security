"""What the onboarding portal stores, and how each item is classified.

General  = Data Pribadi umum   (UU PDP 27/2022, Pasal 4(3)) / GDPR Art. 4(1)
Specific = Data Pribadi spesifik (UU PDP Pasal 4(2)) and/or GDPR Art. 9 special category

Every item below identifies the employee, so every item is personal data and
is encrypted. The classification decides which items carry the higher legal
risk (and would need a DPIA under UU PDP Pasal 34), not whether to encrypt.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    group: str
    level: str  # "general" or "specific"
    basis: str
    multiline: bool = False


FIELDS = [
    Field("full_name", "Full name", "Identity", "general", "UU PDP 4(3)a"),
    Field("nik", "NIK (national ID number)", "Identity", "general",
          "UU PDP 4(3)f; GDPR Art. 87 national identifier"),
    Field("birth", "Place and date of birth", "Identity", "general", "UU PDP 4(3)f"),
    Field("gender", "Gender", "Identity", "general", "UU PDP 4(3)b"),
    Field("nationality", "Nationality", "Identity", "general", "UU PDP 4(3)c"),
    Field("religion", "Religion", "Identity", "specific",
          "General under UU PDP 4(3)d, but special category under GDPR Art. 9(1): stricter rule applied"),
    Field("marital_status", "Marital status", "Identity", "general", "UU PDP 4(3)e"),
    Field("home_address", "Home address", "Contact", "general", "UU PDP 4(3)f", multiline=True),
    Field("phone", "Personal phone", "Contact", "general", "UU PDP 4(3)f"),
    Field("personal_email", "Personal e-mail", "Contact", "general", "UU PDP 4(3)f"),
    Field("npwp", "NPWP (tax ID)", "Payroll", "general", "UU PDP 4(3)f"),
    Field("bank_account", "Salary bank account", "Payroll", "specific",
          "UU PDP 4(2)f personal financial data"),
    Field("bpjs_number", "BPJS Kesehatan number", "Payroll", "general", "UU PDP 4(3)f"),
    Field("blood_type", "Blood type", "Health", "specific", "UU PDP 4(2)a; GDPR Art. 9(1)"),
    Field("medical_notes", "Allergies / conditions for workplace safety", "Health", "specific",
          "UU PDP 4(2)a; GDPR Art. 9(1)", multiline=True),
    Field("dependants", "Dependants for BPJS family cover", "Family", "specific",
          "UU PDP 4(2)e children's data", multiline=True),
    Field("emergency_contact", "Emergency contact", "Family", "general",
          "Third party's data, UU PDP 4(3)f"),
]

FIELDS_BY_NAME = {f.name: f for f in FIELDS}
MAX_FIELD_LENGTH = 2000


@dataclass(frozen=True)
class Category:
    name: str
    label: str
    examples: str
    extensions: tuple[str, ...]
    level: str
    note: str


CATEGORIES = [
    Category("id_scan", "Scanned identity document", "KTP, NPWP card, passport",
             (".jpg", ".jpeg", ".png", ".pdf"), "specific",
             "Shows NIK, religion and face photo; the photo is not biometric data here "
             "because it is never processed for unique identification (GDPR Art. 4(14), Recital 51)"),
    Category("office", "Office document", "Signed contract, CV, diploma, payslip",
             (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".odt", ".ods"), "specific",
             "Contracts and payslips contain salary and bank details (UU PDP 4(2)f)"),
    Category("video", "Video", "Recorded interview, safety-induction sign-off",
             (".mp4", ".webm", ".mov", ".mkv"), "general",
             "Face and voice identify the employee (UU PDP 4(3)f)"),
]

CATEGORIES_BY_NAME = {c.name: c for c in CATEGORIES}
