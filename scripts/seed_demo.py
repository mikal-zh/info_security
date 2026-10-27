"""Create a demo employee with realistic onboarding data.

    python scripts/seed_demo.py

Login: emp-0001 / onboarding-2026. All data is fictitious.
"""

import io
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from PIL import Image, ImageDraw  # noqa: E402

from hrvault import accounts, create_app, db, vault  # noqa: E402

USERNAME, PASSWORD = "emp-0001", "onboarding-2026"

PERSONAL_DATA = {
    "full_name": "Aditya Pratama Putra",
    "nik": "3578012304980001",
    "birth": "Surabaya, 14-04-1998",
    "gender": "Male",
    "nationality": "Indonesian",
    "religion": "Islam",
    "marital_status": "Married",
    "home_address": "Jl. Raya ITS No. 10, Sukolilo, Surabaya 60111",
    "phone": "+62 812-3456-7890",
    "personal_email": "aditya.pratama@example.com",
    "npwp": "09.254.294.3-407.000",
    "bank_account": "Bank Mandiri 141-00-1234567-8",
    "bpjs_number": "0001234567890",
    "blood_type": "O+",
    "medical_notes": "Allergic to penicillin",
    "dependants": "Spouse: Sari Putri (1999); Child: Bima Pratama (2023)",
    "emergency_contact": "Sari Putri (spouse), +62 813-1111-2222",
}


def ktp_scan() -> bytes:
    img = Image.new("RGB", (856, 540), (214, 232, 245))
    d = ImageDraw.Draw(img)
    d.text((300, 20), "PROVINSI JAWA TIMUR - KOTA SURABAYA (SPECIMEN)", fill=(0, 0, 0))
    rows = ["NIK : 3578012304980001", "Nama : ADITYA PRATAMA PUTRA", "Tempat/Tgl Lahir : SURABAYA, 14-04-1998",
            "Jenis Kelamin : LAKI-LAKI", "Alamat : JL. RAYA ITS NO. 10", "Agama : ISLAM",
            "Status Perkawinan : KAWIN", "Pekerjaan : KARYAWAN SWASTA", "Kewarganegaraan : WNI"]
    for i, row in enumerate(rows):
        d.text((40, 80 + i * 40), row, fill=(20, 20, 20))
    d.rectangle([640, 90, 810, 320], fill=(180, 190, 200), outline=(90, 90, 90))
    d.text((690, 200), "PHOTO", fill=(60, 60, 60))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def contract_docx() -> bytes:
    """A minimal valid Word document, built without extra dependencies."""
    paragraphs = [
        "EMPLOYMENT CONTRACT (SPECIMEN)",
        "Employee: Aditya Pratama Putra, NIK 3578012304980001",
        "Position: Logistics Analyst. Start date: 3 November 2026.",
        "Monthly gross salary: IDR 9,500,000, paid to Bank Mandiri 141-00-1234567-8.",
    ] + ["Clause text. " * 40] * 30
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>',
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def interview_video() -> bytes | None:
    if not shutil.which("ffmpeg"):
        print("ffmpeg not found: skipping the demo video (upload one through the UI instead).")
        return None
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "interview.mp4"
        subprocess.run(
            ["ffmpeg", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=25",
             "-f", "lavfi", "-i", "sine=frequency=440", "-t", "20", "-pix_fmt", "yuv420p",
             "-c:v", "libx264", "-c:a", "aac", "-shortest", str(out)],
            check=True,
        )
        return out.read_bytes()


def main():
    app = create_app()
    with app.app_context():
        conn = db.get()
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (USERNAME,)).fetchone():
            print(f"{USERNAME} already exists; delete the instance/ folder to reseed.")
            return
        accounts.register(conn, USERNAME, PASSWORD, app.config["PBKDF2_ITERATIONS"])
        user_id, keys = accounts.login(conn, USERNAME, PASSWORD, app.config["PBKDF2_ITERATIONS"])
        vault.save_personal_data(conn, user_id, keys, PERSONAL_DATA)

        docs = [("id_scan", "ktp_scan.png", "image/png", ktp_scan()),
                ("office", "employment_contract.docx",
                 "application/vnd.openxmlformats-officedocument.wordprocessingml.document", contract_docx())]
        video = interview_video()
        if video:
            docs.append(("video", "interview_recording.mp4", "video/mp4", video))
        for category, name, mime, data in docs:
            vault.store_document(conn, app.config["BLOB_DIR"], user_id, keys, category, name, mime, data)
            print(f"stored {name} ({len(data) / 1024:,.0f} KB) x3")
    print(f"\nDemo ready. Log in as {USERNAME} / {PASSWORD}")


if __name__ == "__main__":
    main()
