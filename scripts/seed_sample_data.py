"""
seed_sample_data.py
Utility script to seed the database with sample GDPR/UU PDP personal data
and sample test files (ID card image, document, and media payload) for AES, DES, and RC4.
"""

import os
import sys
import io
import time
from PIL import Image, ImageDraw

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src import database, crypto_manager

def generate_sample_id_card_image() -> bytes:
    """Generates a clean synthetic mock ID Card (KTP style) PNG image using PIL."""
    width, height = 600, 380
    image = Image.new("RGB", (width, height), color=(240, 244, 248))
    draw = ImageDraw.Draw(image)

    # Header bar (Deep Blue)
    draw.rectangle([0, 0, width, 50], fill=(20, 70, 140))
    draw.text((20, 16), "REPUBLIK INDONESIA - KTP (MOCK)", fill=(255, 255, 255))

    # Photo placeholder
    draw.rectangle([440, 70, 570, 240], fill=(200, 210, 220), outline=(100, 120, 140), width=2)
    draw.text((475, 150), "[PHOTO]", fill=(80, 90, 100))

    fields = [
        "NIK: 3578012304950001",
        "Nama: ADITYA PRATAMA",
        "Tgl Lahir: 14-04-1998",
        "Kelamin: LAKI-LAKI",
        "Alamat: JL. RAYA ITS NO. 10",
        "Agama: ISLAM",
        "Status: BELUM KAWIN",
        "Pekerjaan: MAHASISWA / ENG",
        "WNI - KOTA SURABAYA"
    ]

    y = 80
    for text in fields:
        draw.text((30, y), text, fill=(30, 40, 50))
        y += 28

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()

def generate_sample_document_bytes() -> bytes:
    """Generates a sample PDF document content."""
    header = b"%PDF-1.4\n%Mock Cryptographic Confidential Document for Assignment 1\n"
    payload = b"% Confidential data payload segment\n" * 1500
    trailer = b"%%EOF\n"
    return header + payload + trailer

def generate_sample_video_bytes() -> bytes:
    """Generates synthetic media payload bytes (~256 KB) simulating a video stream."""
    header = b"MP4_VIDEO_HEADER_" + bytes([0, 0, 0, 32])
    payload = b"MPEG4_AVC_VIDEO_FRAME_STREAM_ENCRYPTED_PAYLOAD_ITS_INFOSEC_2026_" * 4000
    return header + payload

def seed():
    print("Initializing Database schema in data/secure_vault.db...")
    database.init_db()

    upload_folder = os.path.join(BASE_DIR, "data", "uploads")
    os.makedirs(upload_folder, exist_ok=True)

    username = "student_group"
    password = "Password123!"

    user = database.authenticate_user(username, password)
    if not user:
        user_id = database.create_user(username, password)
        print(f"Created demo user: '{username}' with password: '{password}' (ID: {user_id})")
    else:
        user_id = user["id"]
        print(f"Existing demo user: '{username}' (ID: {user_id})")

    keys = crypto_manager.derive_keys_from_password(password)
    sample_fields = {
        "full_name": "Aditya Pratama Putra, S.Kom.",
        "nik_id": "3578012304950001",
        "birth_date": "1998-04-14",
        "birth_place": "Surabaya",
        "gender": "Male",
        "religion": "Islam",
        "marital_status": "Single",
        "home_address": "Jl. Raya ITS, Sukolilo, Surabaya, Jawa Timur 60111",
        "phone_number": "+62 812-3456-7890",
        "email_address": "aditya.pratama@its.ac.id",
        "health_info": "Golongan Darah: O, Riwayat Alergi: Debu, Status Vaksin: Dosis 3 Booster",
        "financial_account": "Bank Mandiri No. Rekening: 141-00-1234567-8"
    }

    encrypted_fields = {}
    for k, v in sample_fields.items():
        encrypted_fields[k] = crypto_manager.encrypt_string(v, "AES", keys["AES"])

    database.save_private_data(user_id, "AES", encrypted_fields, iv_hex="seeded_aes_iv")
    print("Seeded encrypted GDPR / UU PDP private data profile for user.")

    test_files = [
        ("id_card", "ktp_identity_card.png", "image/png", generate_sample_id_card_image()),
        ("document", "gdpr_audit_report.pdf", "application/pdf", generate_sample_document_bytes()),
        ("video", "security_surveillance_clip.mp4", "video/mp4", generate_sample_video_bytes())
    ]

    for category, fname, mime, data_bytes in test_files:
        for algo in ["AES", "DES", "RC4"]:
            key = keys[algo]
            payload, meta = crypto_manager.encrypt_bytes(data_bytes, algo, key)

            storage_name = f"enc_{user_id}_{int(time.time()*1000)}_{algo}_{fname}.enc"
            disk_path = os.path.join(upload_folder, storage_name)

            with open(disk_path, "wb") as f_out:
                f_out.write(payload)

            database.save_file_record(
                user_id=user_id,
                category=category,
                original_filename=f"[{algo}] {fname}",
                file_type=mime,
                original_size=len(data_bytes),
                cipher_algorithm=algo,
                storage_filename=storage_name,
                encrypted_size=meta["encrypted_size"],
                encryption_time_ms=meta["time_ms"],
                entropy=meta["entropy"],
                iv_hex=meta["iv_hex"]
            )

        print(f"Seeded '{fname}' in AES, DES, and RC4 formats ({category}).")

    print("\nDatabase and sample files successfully seeded!")
    print(f"Login credentials: Username: '{username}' | Password: '{password}'")

if __name__ == "__main__":
    seed()
