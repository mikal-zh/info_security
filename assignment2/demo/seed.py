# PROJECT, 2026
# info_security
# File description:
# Create a demo employee with realistic onboarding data.

"""Create a demo employee with realistic onboarding data.

    python demo/seed.py

Login: emp-0001 / onboarding-2026. All data is fictitious.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fake_documents  # noqa: E402

from hrvault import accounts, create_app, db, documents, personal  # noqa
from hrvault.owner import Owner  # noqa: E402

DEMO = accounts.Credentials("emp-0001", "onboarding-2026")
DOCX_MIME = ("application/vnd.openxmlformats-officedocument."
             "wordprocessingml.document")

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


def demo_uploads() -> list[documents.Upload]:
    """The KTP scan, the contract and, if ffmpeg exists, the video."""
    uploads = [
        documents.Upload("id_scan", "ktp_scan.png", "image/png",
                         fake_documents.ktp_scan()),
        documents.Upload("office", "employment_contract.docx", DOCX_MIME,
                         fake_documents.contract_docx()),
    ]
    video = fake_documents.interview_video()
    if video:
        uploads.append(documents.Upload("video", "interview_recording.mp4",
                                        "video/mp4", video))
    return uploads


def create_demo_owner(app) -> Owner | None:
    """Register and log in the demo employee; None if they exist."""
    conn = db.get()
    iterations = app.config["PBKDF2_ITERATIONS"]
    if conn.execute("SELECT 1 FROM users WHERE username = ?",
                    (DEMO.username,)).fetchone():
        return None
    accounts.register(conn, DEMO, iterations)
    user_id, keys = accounts.login(conn, DEMO, iterations)
    return Owner(conn, app.config["BLOB_DIR"], user_id, keys)


def main():
    """Seed the demo employee's personal data and documents."""
    app = create_app()
    with app.app_context():
        owner = create_demo_owner(app)
        if owner is None:
            print(f"{DEMO.username} already exists; delete the instance/ "
                  "folder to reseed.")
            return
        personal.save_personal_data(owner, PERSONAL_DATA)
        for upload in demo_uploads():
            documents.store_document(owner, upload)
            print(f"stored {upload.filename} "
                  f"({len(upload.data) / 1024:,.0f} KB) x3")
    print(f"\nDemo ready. Log in as {DEMO.username} / {DEMO.password}")


if __name__ == "__main__":
    main()
