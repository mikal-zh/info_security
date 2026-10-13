"""
database.py
Database management module using SQLite.
Stores user authentication credentials, encrypted private data (GDPR/UU PDP),
and metadata for encrypted file artifacts.
"""

import sqlite3
import os
import hashlib
from typing import Optional, Dict, Any, List

# Locate data/ directory relative to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "secure_vault.db")

def get_db_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hashes a password with PBKDF2-HMAC-SHA256 using a random 16-byte salt and 100,000 iterations.
    Returns: (hex_hash, hex_salt)
    """
    if salt is None:
        salt = os.urandom(16)
    pwd_bytes = password.encode('utf-8')
    derived = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
    return derived.hex(), salt.hex()

def verify_password(password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
    """Verifies a plaintext password against the stored PBKDF2-HMAC-SHA256 hash."""
    salt = bytes.fromhex(stored_salt_hex)
    pwd_bytes = password.encode('utf-8')
    computed_hash = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000).hex()
    return computed_hash == stored_hash_hex

def init_db():
    """Initializes the database schema if not already present."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Encrypted Private Data (GDPR / UU PDP Compliance)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS private_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        cipher_algorithm TEXT NOT NULL, -- 'AES', 'DES', or 'RC4'
        full_name TEXT,
        nik_id TEXT,
        birth_date TEXT,
        birth_place TEXT,
        gender TEXT,
        religion TEXT,
        marital_status TEXT,
        home_address TEXT,
        phone_number TEXT,
        email_address TEXT,
        health_info TEXT,
        financial_account TEXT,
        iv_hex TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 3. Encrypted Stored Files (ID cards, Documents, Videos)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS stored_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL, -- 'id_card', 'document', 'video'
        original_filename TEXT NOT NULL,
        file_type TEXT NOT NULL,
        original_size INTEGER NOT NULL,
        cipher_algorithm TEXT NOT NULL, -- 'AES', 'DES', or 'RC4'
        storage_filename TEXT NOT NULL,
        encrypted_size INTEGER NOT NULL,
        encryption_time_ms REAL NOT NULL,
        entropy REAL,
        iv_hex TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 4. Benchmark Execution History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS benchmark_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        test_label TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        iterations INTEGER NOT NULL,
        aes_enc_avg_ms REAL,
        aes_dec_avg_ms REAL,
        des_enc_avg_ms REAL,
        des_dec_avg_ms REAL,
        rc4_enc_avg_ms REAL,
        rc4_dec_avg_ms REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()

# User Management Functions
def create_user(username: str, password: str) -> Optional[int]:
    """Registers a new user and returns their user_id, or None if username exists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    pwd_hash, salt = hash_password(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username.strip(), pwd_hash, salt)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticates username and password. Returns user dict on success, None on failure."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
    user = cursor.fetchone()
    conn.close()

    if user and verify_password(password, user['password_hash'], user['salt']):
        return dict(user)
    return None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves user row by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# Private Data Functions
def get_private_data(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves encrypted private data row for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM private_data WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def save_private_data(user_id: int, cipher_algorithm: str, fields: Dict[str, str], iv_hex: str = "") -> None:
    """Inserts or updates the user's encrypted private data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM private_data WHERE user_id = ?", (user_id,))
    existing = cursor.fetchone()

    field_keys = [
        'full_name', 'nik_id', 'birth_date', 'birth_place', 'gender',
        'religion', 'marital_status', 'home_address', 'phone_number',
        'email_address', 'health_info', 'financial_account'
    ]

    values = [fields.get(k, '') for k in field_keys]

    if existing:
        cursor.execute(f"""
            UPDATE private_data SET
                cipher_algorithm = ?,
                full_name = ?, nik_id = ?, birth_date = ?, birth_place = ?, gender = ?,
                religion = ?, marital_status = ?, home_address = ?, phone_number = ?,
                email_address = ?, health_info = ?, financial_account = ?,
                iv_hex = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, [cipher_algorithm] + values + [iv_hex, user_id])
    else:
        cursor.execute(f"""
            INSERT INTO private_data (
                user_id, cipher_algorithm,
                full_name, nik_id, birth_date, birth_place, gender,
                religion, marital_status, home_address, phone_number,
                email_address, health_info, financial_account, iv_hex
            ) VALUES (?, ?, {', '.join(['?'] * len(field_keys))}, ?)
        """, [user_id, cipher_algorithm] + values + [iv_hex])

    conn.commit()
    conn.close()

# File Storage Functions
def save_file_record(
    user_id: int,
    category: str,
    original_filename: str,
    file_type: str,
    original_size: int,
    cipher_algorithm: str,
    storage_filename: str,
    encrypted_size: int,
    encryption_time_ms: float,
    entropy: float = 0.0,
    iv_hex: str = ""
) -> int:
    """Inserts metadata record for an encrypted file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO stored_files (
            user_id, category, original_filename, file_type, original_size,
            cipher_algorithm, storage_filename, encrypted_size, encryption_time_ms,
            entropy, iv_hex
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, category, original_filename, file_type, original_size,
        cipher_algorithm, storage_filename, encrypted_size, encryption_time_ms,
        entropy, iv_hex
    ))
    conn.commit()
    file_id = cursor.lastrowid
    conn.close()
    return file_id

def get_user_files(user_id: int, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves list of files for a user, optionally filtered by category."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if category:
        cursor.execute(
            "SELECT * FROM stored_files WHERE user_id = ? AND category = ? ORDER BY created_at DESC",
            (user_id, category)
        )
    else:
        cursor.execute(
            "SELECT * FROM stored_files WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_file_record(file_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves single file metadata record if it belongs to the given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stored_files WHERE id = ? AND user_id = ?", (file_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_file_record(file_id: int, user_id: int) -> Optional[str]:
    """Deletes a file record and returns its storage_filename for disk cleanup."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT storage_filename FROM stored_files WHERE id = ? AND user_id = ?", (file_id, user_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    storage_filename = row['storage_filename']
    cursor.execute("DELETE FROM stored_files WHERE id = ? AND user_id = ?", (file_id, user_id))
    conn.commit()
    conn.close()
    return storage_filename

def record_benchmark(user_id: int, label: str, size_bytes: int, iterations: int, data: Dict[str, Any]):
    """Records a summary of multi-cipher benchmark test for analysis."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO benchmark_history (
            user_id, test_label, file_size_bytes, iterations,
            aes_enc_avg_ms, aes_dec_avg_ms,
            des_enc_avg_ms, des_dec_avg_ms,
            rc4_enc_avg_ms, rc4_dec_avg_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, label, size_bytes, iterations,
        data.get('AES', {}).get('encryption', {}).get('avg_ms', 0),
        data.get('AES', {}).get('decryption', {}).get('avg_ms', 0),
        data.get('DES', {}).get('encryption', {}).get('avg_ms', 0),
        data.get('DES', {}).get('decryption', {}).get('avg_ms', 0),
        data.get('RC4', {}).get('encryption', {}).get('avg_ms', 0),
        data.get('RC4', {}).get('decryption', {}).get('avg_ms', 0)
    ))
    conn.commit()
    conn.close()

