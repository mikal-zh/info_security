# PROJECT, 2026
# info_security
# File description:
# Create a demo employee and an HR officer who asked for their file.

"""Create a demo employee and an HR officer who asked for their file.

    python demo/seed.py

Logins: emp-0001 and hr-0001, both with the password onboarding-2026.
Log in as emp-0001 and open Sharing to approve hr-0001's request. All
data is fictitious.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fake_documents  # noqa: E402

from hrvault import accounts, create_app, db, documents  # noqa: E402
from hrvault import keypairs, personal, sharing  # noqa: E402
from hrvault.owner import Owner  # noqa: E402

DEMO = accounts.Credentials("emp-0001", "onboarding-2026")
HR = accounts.Credentials("hr-0001", "onboarding-2026")
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


def create_demo_owner(app, creds: accounts.Credentials) -> Owner | None:
    """Register and log in a demo user with a key pair; None if present."""
    conn = db.get()
    iterations = app.config["PBKDF2_ITERATIONS"]
    if conn.execute("SELECT 1 FROM users WHERE username = ?",
                    (creds.username,)).fetchone():
        return None
    accounts.register(conn, creds, iterations)
    user_id, keys = accounts.login(conn, creds, iterations)
    owner = Owner(conn, app.config["BLOB_DIR"], user_id, keys)
    keypairs.ensure_key_pair(owner, app.config["RSA_KEY_BITS"])
    return owner


def seed_employee(owner: Owner) -> None:
    """Store the demo employee's personal data and documents."""
    personal.save_personal_data(owner, PERSONAL_DATA)
    for upload in demo_uploads():
        documents.store_document(owner, upload)
        print(f"stored {upload.filename} "
              f"({len(upload.data) / 1024:,.0f} KB) x3")


def main():
    """Seed the demo employee, then the HR officer and their request."""
    app = create_app()
    with app.app_context():
        owner = create_demo_owner(app, DEMO)
        if owner is None:
            print(f"{DEMO.username} already exists; delete the instance/ "
                  "folder to reseed.")
            return
        seed_employee(owner)
        hr_officer = create_demo_owner(app, HR)
        sharing.request_access(db.get(), hr_officer.user_id, DEMO.username)
    print(f"\nDemo ready. Log in as {DEMO.username} / {DEMO.password} and "
          f"approve {HR.username}'s request on the Sharing page.")


if __name__ == "__main__":
    main()
