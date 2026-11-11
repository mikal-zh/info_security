# PROJECT, 2026
# info_security
# File description:
# A one-page specimen employment contract as a PDF, built by hand.

"""A one-page specimen employment contract as a PDF, built by hand."""

CONTRACT_PDF_LINES = [
    "EMPLOYMENT CONTRACT (SPECIMEN)",
    "",
    "Employee: Aditya Pratama Putra, NIK 3578012304980001",
    "Position: Logistics Analyst. Start date: 3 November 2026.",
    "Monthly gross salary: IDR 9,500,000.",
    "",
    "1. The employee works 40 hours per week at the Surabaya office.",
    "2. The probation period is three months.",
    "3. Personal data is processed under UU PDP No. 27/2022.",
    "",
    "Signed digitally by the employee in the Onboarding Vault.",
]


def _text_stream() -> bytes:
    """Page content: the contract lines in 12 pt Helvetica."""
    commands = "BT /F1 12 Tf 16 TL 72 770 Td\n"
    for line in CONTRACT_PDF_LINES:
        escaped = line.replace("\\", "\\\\").replace("(", "\\(")
        commands += "(" + escaped.replace(")", "\\)") + ") '\n"
    return (commands + "ET").encode()


def _objects() -> list[bytes]:
    """Catalog, page tree, page, content stream and font."""
    content = _text_stream()
    return [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]"
        b" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]


def contract_pdf() -> bytes:
    """The contract as a complete PDF with a classic xref table."""
    output = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for number, body in enumerate(_objects(), start=1):
        offsets.append(len(output))
        output += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    start = len(output)
    output += f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f\r\n".encode()
    for offset in offsets:
        output += f"{offset:010d} 00000 n\r\n".encode()
    output += f"trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R >>\n".encode()
    return output + f"startxref\n{start}\n%%EOF\n".encode()
