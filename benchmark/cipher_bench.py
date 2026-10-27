# PROJECT, 2026
# info_security
# File description:
# Cipher-only and cipher+HMAC timings, and the PBKDF2 login cost.

"""Cipher-only and cipher+HMAC timings, and the PBKDF2 login cost.

Timing the raw cipher and the full envelope separately shows the cost of
each cipher apart from the integrity layer they share.
"""

import os
from functools import partial

from timing import summarise, time_ns
from workloads import MB, WORKLOADS, repeats_for

from hrvault.config import Config
from hrvault.crypto import CIPHERS, VaultKeys, ciphers, envelope, keys

CONTEXT = "bench"
OPERATIONS = ("encrypt", "decrypt", "seal", "open")


def _encrypt_all(cipher_keys, items):
    """Raw-encrypt every item."""
    return [ciphers.encrypt(cipher_keys.cipher, cipher_keys.enc_key, item)
            for item in items]


def _decrypt_all(cipher_keys, raw):
    """Raw-decrypt every (nonce, ciphertext) pair."""
    return [ciphers.decrypt(cipher_keys.cipher, cipher_keys.enc_key, nonce,
                            ciphertext) for nonce, ciphertext in raw]


def _seal_all(cipher_keys, items):
    """Encrypt and authenticate every item."""
    return [envelope.seal(cipher_keys, item, CONTEXT) for item in items]


def _open_all(cipher_keys, sealed):
    """Verify and decrypt every envelope."""
    return [envelope.open_(cipher_keys, item, CONTEXT) for item in sealed]


def _measure(cipher_keys, items, repeats: int) -> dict:
    """Timing summary of the four operations for one cipher."""
    operations = {
        "encrypt": partial(_encrypt_all, cipher_keys, items),
        "decrypt": partial(_decrypt_all, cipher_keys,
                           _encrypt_all(cipher_keys, items)),
        "seal": partial(_seal_all, cipher_keys, items),
        "open": partial(_open_all, cipher_keys,
                        _seal_all(cipher_keys, items)),
    }
    return {name: summarise(time_ns(func, repeats, warmup=2))
            for name, func in operations.items()}


def _workload_rows(workload, cipher_keys, quick: bool) -> list[dict]:
    """One result row per operation for a workload and a cipher."""
    name, size, count = workload
    items = [os.urandom(size) for _ in range(count)]
    total = size * count
    summaries = _measure(cipher_keys, items, repeats_for(total, quick))
    overhead = count * envelope.overhead(cipher_keys.cipher, size)
    return [{"workload": name, "bytes": total, "cipher": cipher_keys.cipher,
             "op": op, **summary,
             "throughput_MBps": total / MB / (summary["median_ms"] / 1000),
             "overhead_bytes": overhead}
            for op, summary in summaries.items()]


def bench_ciphers(quick: bool) -> list[dict]:
    """Time every operation of every cipher on every workload."""
    vault = VaultKeys.generate()
    rows = []
    for workload in WORKLOADS:
        for cipher in CIPHERS:
            rows += _workload_rows(workload, vault.cipher_keys(cipher), quick)
            print(f"  {workload[0]:24s} {cipher}: open median "
                  f"{rows[-1]['median_ms']:9.3f} ms", flush=True)
    return rows


def bench_login(quick: bool) -> dict:
    """Time one PBKDF2 derivation, paid once per login."""
    derive = partial(keys.derive_login_secrets, "benchmark-password",
                     keys.new_salt(), Config.PBKDF2_ITERATIONS)
    samples = time_ns(derive, 3 if quick else 11, warmup=1)
    return {"iterations": Config.PBKDF2_ITERATIONS, **summarise(samples)}
