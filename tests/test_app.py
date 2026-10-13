"""
test_app.py
Comprehensive automated test suite for the Information Security web application.
Tests authentication, private data encryption/decryption, file vault operations,
download decryption integrity, benchmarking endpoints, and report viewer.
"""

import unittest
import io
import json
import os
import sys
import uuid

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from src import database

class SecurityAppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        # Generate unique user for each test to ensure test isolation
        uid = uuid.uuid4().hex[:8]
        self.username = f"eval_{uid}"
        self.password = "SecTest2026!"
        database.create_user(self.username, self.password)

    def login(self):
        return self.client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)

    def test_01_authentication_flow(self):
        """Test registration, duplicate username rejection, login, and logout."""
        unique_new = f"new_{uuid.uuid4().hex[:8]}"
        # 1. New user registration
        resp = self.client.post('/register', data={
            'username': unique_new,
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Registration successful", resp.data)

        # 2. Duplicate registration rejection
        resp_dup = self.client.post('/register', data={
            'username': unique_new,
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }, follow_redirects=True)
        self.assertIn(b"Username already exists", resp_dup.data)

        # 3. Successful login
        resp_login = self.login()
        self.assertEqual(resp_login.status_code, 200)
        self.assertIn(b"Welcome", resp_login.data)

        # 4. Logout
        resp_logout = self.client.get('/logout', follow_redirects=True)
        self.assertIn(b"securely logged out", resp_logout.data)

    def test_02_private_data_encryption_and_retrieval(self):
        """Test storing and decrypting GDPR/UU PDP personal data under AES, DES, and RC4."""
        self.login()

        for cipher in ['AES', 'DES', 'RC4']:
            payload = {
                'cipher_algorithm': cipher,
                'full_name': f'Confidential Citizen {cipher}',
                'nik_id': '3271012345678901',
                'birth_date': '1995-10-15',
                'birth_place': 'Bandung',
                'gender': 'Male',
                'religion': 'Islam',
                'marital_status': 'Single',
                'home_address': 'Jl. Ganesha No. 10',
                'phone_number': '+62 811-2233-4455',
                'email_address': 'student@univ.ac.id',
                'health_info': 'O Positive, No Allergies',
                'financial_account': 'Bank Mandiri 130-00-9876543-2'
            }

            resp = self.client.post('/profile', data=payload, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(f"encrypted and saved using {cipher}".encode('utf-8'), resp.data)

            # GET profile to ensure plaintext is correctly decrypted
            get_resp = self.client.get('/profile')
            self.assertEqual(get_resp.status_code, 200)
            self.assertIn(f'Confidential Citizen {cipher}'.encode('utf-8'), get_resp.data)
            self.assertIn(b'3271012345678901', get_resp.data)

            # Direct database inspection to verify that zero plaintext is stored
            conn = database.get_db_connection()
            row = conn.execute("SELECT * FROM private_data WHERE user_id = (SELECT id FROM users WHERE username = ?)", (self.username,)).fetchone()
            conn.close()

            self.assertIsNotNone(row)
            self.assertEqual(row['cipher_algorithm'], cipher)
            self.assertNotEqual(row['full_name'], f'Confidential Citizen {cipher}')
            self.assertNotEqual(row['nik_id'], '3271012345678901')

    def test_03_file_upload_encryption_and_decrypted_download(self):
        """Test uploading file, verifying disk encryption, and downloading decrypted content."""
        self.login()

        sample_original_content = b"CRITICAL_CLASSIFIED_EVALUATION_DOCUMENT_TEST_PAYLOAD" * 50

        for algo in ['AES', 'DES', 'RC4']:
            file_data = (io.BytesIO(sample_original_content), f"secret_doc_{algo}.pdf")
            resp = self.client.post('/files/upload', data={
                'category': 'document',
                'cipher_algorithm': algo,
                'file': file_data
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

            # Query database to get saved file record
            conn = database.get_db_connection()
            file_row = conn.execute(
                "SELECT * FROM stored_files WHERE original_filename = ? AND user_id = (SELECT id FROM users WHERE username = ?) ORDER BY id DESC LIMIT 1",
                (f"secret_doc_{algo}.pdf", self.username)
            ).fetchone()
            conn.close()

            self.assertIsNotNone(file_row)
            self.assertEqual(file_row['cipher_algorithm'], algo)

            # Verify that disk file is NOT plaintext
            storage_path = os.path.join(app.config['UPLOAD_FOLDER'], file_row['storage_filename'])
            self.assertTrue(os.path.exists(storage_path))
            with open(storage_path, 'rb') as f:
                disk_bytes = f.read()
            self.assertNotEqual(disk_bytes, sample_original_content)

            # Download decrypted file and verify bit-for-bit integrity
            dl_resp = self.client.get(f"/files/download/{file_row['id']}")
            self.assertEqual(dl_resp.status_code, 200)
            self.assertEqual(dl_resp.data, sample_original_content)

    def test_04_benchmark_api(self):
        """Test the multi-iteration benchmark API simulating repeated download runs."""
        self.login()

        payload = {
            'synthetic_size_kb': 128,
            'iterations': 5
        }
        resp = self.client.post('/api/benchmark/run', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        self.assertIn('ciphers', data)
        self.assertIn('AES', data['ciphers'])
        self.assertIn('DES', data['ciphers'])
        self.assertIn('RC4', data['ciphers'])
        self.assertEqual(len(data['ciphers']['AES']['decryption']['runs']), 5)
        self.assertGreater(data['ciphers']['AES']['entropy'], 7.9)

    def test_05_report_page(self):
        """Test report viewer endpoint."""
        self.login()
        resp = self.client.get('/report')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Cryptographic Evaluation", resp.data)

if __name__ == '__main__':
    unittest.main()

