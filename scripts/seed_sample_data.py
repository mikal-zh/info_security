"""
seed_sample_data.py
Utility script to seed the database with sample GDPR/UU PDP personal data
and sample test files (ID card image, document, and media payload) for AES, DES, and RC4.
"""

import os
import sys
import io
import time
import numpy as np
import cv2

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src import database, crypto_manager

def generate_sample_id_card_image() -> bytes:
    """Generates a synthetic mock ID Card (KTP style) image in PNG format using OpenCV."""
    width, height = 600, 380
    image = np.full((height, width, 3), (54, 34, 24), dtype=np.uint8)

    # Header bar (Cyan/Teal: BGR 144, 116, 14)
    cv2.rectangle(image, (0, 0), (width, 50), (144, 116, 14), -1)
    cv2.putText(image, "REPUBLIK INDONESIA - KTP (MOCK)", (20, 32),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)

    # Photo placeholder (BGR: 105, 85, 71)
    cv2.rectangle(image, (440, 70), (570, 240), (105, 85, 71), -1)
    cv2.rectangle(image, (440, 70), (570, 240), (184, 163, 148), 2)
    cv2.putText(image, "[PHOTO]", (465, 160),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (225, 213, 203), 1)

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

    y = 85
    for text in fields:
        cv2.putText(image, text, (30, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.48, (249, 245, 241), 1)
        y += 28

    success, encoded = cv2.imencode('.png', image)
    if success:
        return encoded.tobytes()
    return b"ID_CARD_FALLBACK_BYTES"

def generate_sample_document_bytes() -> bytes:
    """Generates a sample PDF document content."""
    content = (
        "%PDF-1.4\n"
        "%Mock Cryptographic Confidential Document for Assignment 1\n"
        "1 0 obj << /Title (Confidential Security Evaluation Report) /Author (Group 4) >> endobj\n"
        "2 0 obj << /Type /Catalog /Pages 3 0 R >> endobj\n"
        "3 0 obj << /Type /Pages /Count 1 /Kids [4 0 R] >> endobj\n"
        "4 0 obj << /Type /Page /Parent 3 0 R /Contents 5 0 R >> endobj\n"
        "5 0 obj << /Length 420 >> stream\n"
        "BT /F1 12 Tf 50 750 Td (This document contains sensitive corporate financial statements and GDPR records.) Tj ET\n"
        "BT /F1 12 Tf 50 720 Td (All information is encrypted under AES-256-CBC, DES-CBC, and RC4.) Tj ET\n"
        "BT /F1 12 Tf 50 690 Td (Audit Compliance: UU No. 27/2022 on Personal Data Protection.) Tj ET\n"
        "endstream endobj\n"
        "xref\n0 6\n0000000000 65535 f \n"
        "trailer << /Size 6 /Root 2 0 R >>\n"
        "startxref\n500\n%%EOF\n"
    )
    extra = ("\n% SECTION " + "="*40 + "\n% Confidential encrypted payload data segment\n") * 350
    return (content + extra).encode('utf-8')

def generate_sample_video_bytes() -> bytes:
    """Generates synthetic media payload bytes (~256 KB) simulating a video stream."""
    header = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2avc1mp41"
    moov_chunk = b"\x00\x00\x01\x00moov\x00\x00\x00\x6ctkhd\x00\x00\x00\x01" + (b"\xaa\x55" * 100)
    mdat_pattern = b"MPEG4_AVC_VIDEO_FRAME_STREAM_ENCRYPTED_PAYLOAD_ITS_INFOSEC_2026_" * 4000
    return header + moov_chunk + mdat_pattern

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
        user_id = user['id']
        print(f"Existing demo user: '{username}' (ID: {user_id})")

    # Seed GDPR / UU PDP Private Data
    keys = crypto_manager.derive_keys_from_password(password)
    sample_fields = {
        'full_name': 'Aditya Pratama Putra, S.Kom.',
        'nik_id': '3578012304950001',
        'birth_date': '1998-04-14',
        'birth_place': 'Surabaya',
        'gender': 'Male',
        'religion': 'Islam',
        'marital_status': 'Single',
        'home_address': 'Jl. Raya ITS, Sukolilo, Surabaya, Jawa Timur 60111',
        'phone_number': '+62 812-3456-7890',
        'email_address': 'aditya.pratama@its.ac.id',
        'health_info': 'Golongan Darah: O, Riwayat Alergi: Debu, Status Vaksin: Dosis 3 Booster',
        'financial_account': 'Bank Mandiri No. Rekening: 141-00-1234567-8'
    }

    encrypted_fields = {}
    for k, v in sample_fields.items():
        encrypted_fields[k] = crypto_manager.encrypt_string(v, 'AES', keys['AES'])

    database.save_private_data(user_id, 'AES', encrypted_fields, iv_hex="seeded_aes_iv")
    print("Seeded encrypted GDPR / UU PDP private data profile for user.")

    # Seed Sample Files
    test_files = [
        ("id_card", "ktp_identity_card.png", "image/png", generate_sample_id_card_image()),
        ("document", "gdpr_audit_report.pdf", "application/pdf", generate_sample_document_bytes()),
        ("video", "security_surveillance_clip.mp4", "video/mp4", generate_sample_video_bytes())
    ]

    for category, fname, mime, data_bytes in test_files:
        for algo in ['AES', 'DES', 'RC4']:
            key = keys[algo]
            payload, meta = crypto_manager.encrypt_bytes(data_bytes, algo, key)

            storage_name = f"enc_{user_id}_{int(time.time()*1000)}_{algo}_{fname}.enc"
            disk_path = os.path.join(upload_folder, storage_name)

            with open(disk_path, 'wb') as f_out:
                f_out.write(payload)

            database.save_file_record(
                user_id=user_id,
                category=category,
                original_filename=f"[{algo}] {fname}",
                file_type=mime,
                original_size=len(data_bytes),
                cipher_algorithm=algo,
                storage_filename=storage_name,
                encrypted_size=meta['encrypted_size'],
                encryption_time_ms=meta['time_ms'],
                entropy=meta['entropy'],
                iv_hex=meta['iv_hex']
            )

        print(f"Seeded '{fname}' in AES, DES, and RC4 formats ({category}).")

    print("\nDatabase and sample files successfully seeded!")
    print(f"Login credentials: Username: '{username}' | Password: '{password}'")

if __name__ == '__main__':
    seed()

