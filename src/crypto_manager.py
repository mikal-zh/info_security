"""
crypto_manager.py
Cryptographic engine providing AES, DES, and RC4 implementations.
Complies with non-ECB block cipher requirement using CBC mode with PKCS#7 padding and secure random IVs.
Includes high-resolution execution time profiling and ciphertext analysis.
"""

import os
import time
import base64
import math
from typing import Tuple, Dict, Any

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Constants
BLOCK_SIZE_AES = 16  # 128 bits
BLOCK_SIZE_DES = 8   # 64 bits
KEY_SIZE_AES = 32    # 256 bits (AES-256)
KEY_SIZE_DES = 8     # 64 bits (56-bit effective key + 8 parity bits)
KEY_SIZE_RC4 = 16    # 128 bits

# Salt for app-level key derivation if needed
APP_SALT = b"SecureVault_UU_PDP_GDPR_Salt_2026"

def derive_keys_from_password(password: str, salt: bytes = APP_SALT) -> Dict[str, bytes]:
    """
    Derives standard-length keys for AES-256, DES, and RC4 from a user passphrase
    using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    """
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    # Derive 56 bytes total: 32 bytes for AES-256, 8 bytes for DES, 16 bytes for RC4
    derived = PBKDF2(password_bytes, salt, dkLen=56, count=100000, hmac_hash_module=SHA256)
    
    aes_key = derived[0:32]      # 32 bytes = 256 bits
    des_key = derived[32:40]     # 8 bytes = 64 bits (standard DES key length)
    rc4_key = derived[40:56]     # 16 bytes = 128 bits (standard RC4 key length)

    return {
        'AES': aes_key,
        'DES': des_key,
        'RC4': rc4_key
    }

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0). High entropy ~ 7.9-8.0 is expected for good ciphertext."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    for count in byte_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def encrypt_bytes(data: bytes, cipher_name: str, key: bytes = None) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypts raw bytes using specified cipher (AES, DES, RC4).
    Block ciphers (AES, DES) use CBC mode with PKCS7 padding.
    The resulting payload prepends the IV: [IV (16 or 8 bytes)] + [Ciphertext].
    RC4 does not use IV or padding (stream cipher).
    
    Returns:
        (encrypted_payload, metadata_dict)
    """
    cipher_upper = cipher_name.upper()
    start_time = time.perf_counter_ns()
    
    if cipher_upper == 'AES':
        # Default key if not provided
        if key is None:
            key = derive_keys_from_password("default_secret_key")['AES']
        elif len(key) not in (16, 24, 32):
            key = PBKDF2(key, APP_SALT, dkLen=32, count=10000, hmac_hash_module=SHA256)
            
        iv = get_random_bytes(BLOCK_SIZE_AES)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_data = pad(data, BLOCK_SIZE_AES)
        raw_ciphertext = cipher.encrypt(padded_data)
        # Final payload: IV + Ciphertext
        payload = iv + raw_ciphertext
        padding_bytes_added = len(padded_data) - len(data)
        iv_hex = iv.hex()

    elif cipher_upper == 'DES':
        if key is None:
            key = derive_keys_from_password("default_secret_key")['DES']
        elif len(key) != 8:
            key = PBKDF2(key, APP_SALT, dkLen=8, count=10000, hmac_hash_module=SHA256)
            
        iv = get_random_bytes(BLOCK_SIZE_DES)
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        padded_data = pad(data, BLOCK_SIZE_DES)
        raw_ciphertext = cipher.encrypt(padded_data)
        # Final payload: IV + Ciphertext
        payload = iv + raw_ciphertext
        padding_bytes_added = len(padded_data) - len(data)
        iv_hex = iv.hex()

    elif cipher_upper == 'RC4':
        if key is None:
            key = derive_keys_from_password("default_secret_key")['RC4']
        elif len(key) != 16:
            key = PBKDF2(key, APP_SALT, dkLen=16, count=10000, hmac_hash_module=SHA256)
            
        cipher = ARC4.new(key)
        raw_ciphertext = cipher.encrypt(data)
        payload = raw_ciphertext
        padding_bytes_added = 0
        iv_hex = "None (Stream Cipher)"

    else:
        raise ValueError(f"Unsupported cipher: {cipher_name}. Supported ciphers are AES, DES, RC4.")

    elapsed_ns = time.perf_counter_ns() - start_time
    elapsed_ms = elapsed_ns / 1_000_000.0

    metadata = {
        'algorithm': cipher_upper,
        'mode': 'CBC' if cipher_upper in ('AES', 'DES') else 'Stream',
        'key_size_bits': len(key) * 8,
        'original_size': len(data),
        'encrypted_size': len(payload),
        'padding_bytes_added': padding_bytes_added,
        'overhead_bytes': len(payload) - len(data),
        'iv_hex': iv_hex,
        'entropy': calculate_entropy(payload),
        'time_ms': round(elapsed_ms, 4),
        'time_ns': elapsed_ns
    }

    return payload, metadata

def decrypt_bytes(payload: bytes, cipher_name: str, key: bytes = None) -> Tuple[bytes, Dict[str, Any]]:
    """
    Decrypts encrypted payload using specified cipher (AES, DES, RC4).
    For CBC mode (AES, DES), extracts IV from the initial bytes, decrypts, and unpads.
    
    Returns:
        (decrypted_bytes, metadata_dict)
    """
    cipher_upper = cipher_name.upper()
    start_time = time.perf_counter_ns()

    if cipher_upper == 'AES':
        if key is None:
            key = derive_keys_from_password("default_secret_key")['AES']
        elif len(key) not in (16, 24, 32):
            key = PBKDF2(key, APP_SALT, dkLen=32, count=10000, hmac_hash_module=SHA256)
            
        if len(payload) < BLOCK_SIZE_AES:
            raise ValueError("Ciphertext is too short to contain AES IV and data.")
            
        iv = payload[:BLOCK_SIZE_AES]
        raw_ciphertext = payload[BLOCK_SIZE_AES:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(raw_ciphertext)
        plaintext = unpad(decrypted_padded, BLOCK_SIZE_AES)
        iv_hex = iv.hex()

    elif cipher_upper == 'DES':
        if key is None:
            key = derive_keys_from_password("default_secret_key")['DES']
        elif len(key) != 8:
            key = PBKDF2(key, APP_SALT, dkLen=8, count=10000, hmac_hash_module=SHA256)
            
        if len(payload) < BLOCK_SIZE_DES:
            raise ValueError("Ciphertext is too short to contain DES IV and data.")
            
        iv = payload[:BLOCK_SIZE_DES]
        raw_ciphertext = payload[BLOCK_SIZE_DES:]
        
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(raw_ciphertext)
        plaintext = unpad(decrypted_padded, BLOCK_SIZE_DES)
        iv_hex = iv.hex()

    elif cipher_upper == 'RC4':
        if key is None:
            key = derive_keys_from_password("default_secret_key")['RC4']
        elif len(key) != 16:
            key = PBKDF2(key, APP_SALT, dkLen=16, count=10000, hmac_hash_module=SHA256)
            
        cipher = ARC4.new(key)
        plaintext = cipher.decrypt(payload)
        iv_hex = "None (Stream Cipher)"

    else:
        raise ValueError(f"Unsupported cipher: {cipher_name}.")

    elapsed_ns = time.perf_counter_ns() - start_time
    elapsed_ms = elapsed_ns / 1_000_000.0

    metadata = {
        'algorithm': cipher_upper,
        'mode': 'CBC' if cipher_upper in ('AES', 'DES') else 'Stream',
        'original_encrypted_size': len(payload),
        'decrypted_size': len(plaintext),
        'iv_hex': iv_hex,
        'time_ms': round(elapsed_ms, 4),
        'time_ns': elapsed_ns
    }

    return plaintext, metadata

def encrypt_string(text: str, cipher_name: str, key: bytes = None) -> str:
    """Convenience helper: encrypts text string and returns URL-safe Base64 string."""
    if text is None:
        return ""
    data = text.encode('utf-8')
    payload, _ = encrypt_bytes(data, cipher_name, key)
    return base64.b64encode(payload).decode('utf-8')

def decrypt_string(b64_payload: str, cipher_name: str, key: bytes = None) -> str:
    """Convenience helper: decrypts Base64 string and returns decoded text."""
    if not b64_payload:
        return ""
    try:
        payload = base64.b64decode(b64_payload.encode('utf-8'))
        plaintext, _ = decrypt_bytes(payload, cipher_name, key)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"[Decryption Error: {str(e)}]"

def run_benchmark_on_data(data: bytes, key_pass: str = "benchmark_secret", iterations: int = 10) -> Dict[str, Any]:
    """
    Performs benchmark analysis on the given data across AES, DES, and RC4.
    Runs encryption and decryption multiple times (iterations) and calculates
    average, min, max, std deviation running time, throughput (MB/s), and ciphertext metrics.
    """
    keys = derive_keys_from_password(key_pass)
    results = {}
    
    algorithms = ['AES', 'DES', 'RC4']
    
    data_size_bytes = len(data)
    data_size_kb = data_size_bytes / 1024.0
    data_size_mb = data_size_bytes / (1024.0 * 1024.0)

    for algo in algorithms:
        key = keys[algo]
        enc_times_ms = []
        dec_times_ms = []
        
        # Initial run to get sample ciphertext and metadata
        sample_ciphertext, enc_meta = encrypt_bytes(data, algo, key)
        _, dec_meta = decrypt_bytes(sample_ciphertext, algo, key)

        # Multi-run benchmarking
        for _ in range(iterations):
            # Encryption run
            t0 = time.perf_counter_ns()
            ct, _ = encrypt_bytes(data, algo, key)
            t1 = time.perf_counter_ns()
            enc_times_ms.append((t1 - t0) / 1_000_000.0)

            # Decryption run (simulate repeated download / retrieval)
            t2 = time.perf_counter_ns()
            pt, _ = decrypt_bytes(ct, algo, key)
            t3 = time.perf_counter_ns()
            dec_times_ms.append((t3 - t2) / 1_000_000.0)

        # Statistical calculations
        def stats(arr):
            n = len(arr)
            avg = sum(arr) / n
            variance = sum((x - avg) ** 2 for x in arr) / n if n > 1 else 0
            std_dev = math.sqrt(variance)
            return {
                'avg_ms': round(avg, 4),
                'min_ms': round(min(arr), 4),
                'max_ms': round(max(arr), 4),
                'std_dev_ms': round(std_dev, 4),
                'runs': [round(x, 4) for x in arr]
            }

        enc_stats = stats(enc_times_ms)
        dec_stats = stats(dec_times_ms)

        # Calculate Throughput (MB/s)
        # throughput = size_in_MB / (time_in_seconds)
        enc_avg_sec = (enc_stats['avg_ms'] / 1000.0) if enc_stats['avg_ms'] > 0 else 0.000001
        dec_avg_sec = (dec_stats['avg_ms'] / 1000.0) if dec_stats['avg_ms'] > 0 else 0.000001
        
        enc_throughput_mb_s = round(data_size_mb / enc_avg_sec, 2) if data_size_mb > 0 else 0
        dec_throughput_mb_s = round(data_size_mb / dec_avg_sec, 2) if data_size_mb > 0 else 0

        # Preview ciphertext (first 64 bytes in hex and base64)
        ct_preview_hex = sample_ciphertext[:64].hex()
        ct_preview_b64 = base64.b64encode(sample_ciphertext[:64]).decode('utf-8')

        results[algo] = {
            'algorithm': algo,
            'mode': enc_meta['mode'],
            'key_size_bits': enc_meta['key_size_bits'],
            'original_size_bytes': data_size_bytes,
            'ciphertext_size_bytes': len(sample_ciphertext),
            'overhead_bytes': len(sample_ciphertext) - data_size_bytes,
            'padding_bytes': enc_meta['padding_bytes_added'],
            'entropy': enc_meta['entropy'],
            'iv_hex': enc_meta['iv_hex'],
            'ciphertext_preview_hex': ct_preview_hex,
            'ciphertext_preview_b64': ct_preview_b64,
            'iterations': iterations,
            'encryption': enc_stats,
            'decryption': dec_stats,
            'enc_throughput_mb_s': enc_throughput_mb_s,
            'dec_throughput_mb_s': dec_throughput_mb_s
        }

    return {
        'input_size_bytes': data_size_bytes,
        'input_size_kb': round(data_size_kb, 2),
        'input_size_mb': round(data_size_mb, 4),
        'iterations': iterations,
        'ciphers': results
    }

