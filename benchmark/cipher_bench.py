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


def _encrypt_all(cipher_keys, items):
    """Raw-encrypt every item."""
    results = []
    for item in items:
        nonce_and_ciphertext = ciphers.encrypt(cipher_keys.cipher,
                                               cipher_keys.enc_key, item)
        results.append(nonce_and_ciphertext)
    return results


def _decrypt_all(cipher_keys, raw):
    """Raw-decrypt every (nonce, ciphertext) pair."""
    results = []
    for nonce, ciphertext in raw:
        plaintext = ciphers.decrypt(cipher_keys.cipher, cipher_keys.enc_key,
                                    nonce, ciphertext)
        results.append(plaintext)
    return results


def _seal_all(cipher_keys, items):
    """Encrypt and authenticate every item."""
    results = []
    for item in items:
        results.append(envelope.seal(cipher_keys, item, CONTEXT))
    return results


def _open_all(cipher_keys, sealed):
    """Verify and decrypt every envelope."""
    results = []
    for item in sealed:
        results.append(envelope.open_(cipher_keys, item, CONTEXT))
    return results


def _measure(cipher_keys, items, repeats: int) -> dict:
    """Timing summary of the four operations for one cipher."""
    raw = _encrypt_all(cipher_keys, items)
    sealed = _seal_all(cipher_keys, items)
    operations = {
        "encrypt": partial(_encrypt_all, cipher_keys, items),
        "decrypt": partial(_decrypt_all, cipher_keys, raw),
        "seal": partial(_seal_all, cipher_keys, items),
        "open": partial(_open_all, cipher_keys, sealed),
    }
    summaries = {}
    for name, func in operations.items():
        samples = time_ns(func, repeats, warmup=2)
        summaries[name] = summarise(samples)
    return summaries


def _result_row(base: dict, op: str, summary: dict) -> dict:
    """One CSV row: workload, cipher, operation, timings and throughput."""
    row = {"workload": base["workload"], "bytes": base["bytes"],
           "cipher": base["cipher"], "op": op}
    row.update(summary)
    seconds = summary["median_ms"] / 1000
    row["throughput_MBps"] = base["bytes"] / MB / seconds
    row["overhead_bytes"] = base["overhead_bytes"]
    return row


def _workload_rows(workload, cipher_keys, quick: bool) -> list[dict]:
    """One result row per operation for a workload and a cipher."""
    name, size, count = workload
    items = []
    for _ in range(count):
        items.append(os.urandom(size))
    total = size * count
    summaries = _measure(cipher_keys, items, repeats_for(total, quick))
    base = {"workload": name, "bytes": total, "cipher": cipher_keys.cipher,
            "overhead_bytes": count * envelope.overhead(cipher_keys.cipher,
                                                        size)}
    rows = []
    for op, summary in summaries.items():
        rows.append(_result_row(base, op, summary))
    return rows


def bench_ciphers(quick: bool) -> list[dict]:
    """Time every operation of every cipher on every workload."""
    vault = VaultKeys.generate()
    rows = []
    for workload in WORKLOADS:
        for cipher in CIPHERS:
            cipher_keys = vault.cipher_keys(cipher)
            rows += _workload_rows(workload, cipher_keys, quick)
            print(f"  {workload[0]:24s} {cipher}: open median "
                  f"{rows[-1]['median_ms']:9.3f} ms", flush=True)
    return rows


def bench_login(quick: bool) -> dict:
    """Time one PBKDF2 derivation, paid once per login."""
    derive = partial(keys.derive_login_secrets, "benchmark-password",
                     keys.new_salt(), Config.PBKDF2_ITERATIONS)
    repeats = 11
    if quick:
        repeats = 3
    samples = time_ns(derive, repeats, warmup=1)
    return {"iterations": Config.PBKDF2_ITERATIONS, **summarise(samples)}
