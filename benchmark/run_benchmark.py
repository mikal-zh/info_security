"""Benchmark AES-256-CBC, DES-CBC and RC4-drop3072 on the onboarding workloads.

    python benchmark/run_benchmark.py            # full run, writes benchmark/results/
    python benchmark/run_benchmark.py --quick    # fewer repetitions, for a smoke test

What is measured and why:
  1. cipher only (encrypt/decrypt) vs. full envelope (cipher + HMAC-SHA256):
     separates the cost of each cipher from the integrity layer they share
  2. workloads sized like the real onboarding items: one field, the whole
     form (17 fields), a KTP scan, a contract PDF and an interview video
  3. the login cost (PBKDF2), which every employee pays once per session
  4. end-to-end download through the Flask app, to see what share of a real
     request is spent in the cipher
Timing: time.perf_counter_ns, GC disabled while timing, warm-up runs
discarded, median and interquartile range reported (robust to outliers from
scheduler noise). Inputs are random bytes; cipher speed does not depend on
content, and random data avoids accidental caching or compression effects.
"""

import argparse
import csv
import gc
import io
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import Crypto  # noqa: E402

from hrvault import accounts, create_app, db, vault  # noqa: E402
from hrvault.catalog import FIELDS  # noqa: E402
from hrvault.crypto import CIPHERS, VaultKeys, ciphers, envelope, keys  # noqa: E402
from hrvault.config import Config  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
KB, MB = 1024, 1024 * 1024

# (name, size of one item, items per operation)
WORKLOADS = [
    ("single field (NIK)", 16, 1),
    ("full form (17 fields)", 40, len(FIELDS)),
    ("KTP scan", 400 * KB, 1),
    ("contract PDF", 2 * MB, 1),
    ("interview video", 30 * MB, 1),
]


def time_ns(fn, repeats: int, warmup: int) -> list[int]:
    for _ in range(warmup):
        fn()
    samples = []
    gc.disable()
    try:
        for _ in range(repeats):
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
    finally:
        gc.enable()
    return samples


def summarise(samples_ns: list[int]) -> dict:
    ms = sorted(s / 1e6 for s in samples_ns)
    q = statistics.quantiles(ms, n=4) if len(ms) >= 4 else [ms[0], statistics.median(ms), ms[-1]]
    return {"median_ms": statistics.median(ms), "q1_ms": q[0], "q3_ms": q[2], "n": len(ms)}


def repeats_for(total_bytes: int, quick: bool) -> int:
    if quick:
        return 5
    return 15 if total_bytes >= 10 * MB else 51


def bench_ciphers(quick: bool) -> list[dict]:
    vk = VaultKeys.generate()
    rows = []
    for name, size, count in WORKLOADS:
        items = [os.urandom(size) for _ in range(count)]
        total = size * count
        n = repeats_for(total, quick)
        for c in CIPHERS:
            k, mk = vk.enc_key(c), vk.mac_key(c)
            raw = [ciphers.encrypt(c, k, p) for p in items]
            sealed = [envelope.seal(c, k, mk, p, "bench") for p in items]
            measures = {
                "encrypt": lambda: [ciphers.encrypt(c, k, p) for p in items],
                "decrypt": lambda: [ciphers.decrypt(c, k, nonce, ct) for nonce, ct in raw],
                "seal": lambda: [envelope.seal(c, k, mk, p, "bench") for p in items],
                "open": lambda: [envelope.open_(c, k, mk, s, "bench") for s in sealed],
            }
            for op, fn in measures.items():
                s = summarise(time_ns(fn, n, warmup=2))
                rows.append({
                    "workload": name, "bytes": total, "cipher": c, "op": op, **s,
                    "throughput_MBps": total / MB / (s["median_ms"] / 1000),
                    "overhead_bytes": sum(envelope.overhead(c, size) for _ in items),
                })
            print(f"  {name:24s} {c}: open median {rows[-1]['median_ms']:9.3f} ms", flush=True)
    return rows


def bench_login(quick: bool) -> dict:
    salt = keys.new_salt()
    n = 3 if quick else 11
    s = summarise(time_ns(lambda: keys.derive_login_secrets("benchmark-password", salt, Config.PBKDF2_ITERATIONS),
                          n, warmup=1))
    return {"iterations": Config.PBKDF2_ITERATIONS, **s}


def bench_download(quick: bool) -> list[dict]:
    """Full HTTP request through the app (test client, no network): read, HMAC, decrypt, SHA-256, send."""
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app({"DATA_DIR": Path(tmp), "PBKDF2_ITERATIONS": 1000})
        with app.app_context():
            conn = db.get()
            accounts.register(conn, "bench", "benchmark-pass", 1000)
            uid, vk = accounts.login(conn, "bench", "benchmark-pass", 1000)
            ids = {}
            for name, size, _ in WORKLOADS[2:]:
                vault.store_document(conn, app.config["BLOB_DIR"], uid, vk, "office", f"{name}.bin",
                                     "application/octet-stream", os.urandom(size))
                ids[name] = conn.execute("SELECT MAX(id) FROM documents").fetchone()[0]
        client = app.test_client()
        html = client.get("/login").get_data(as_text=True)
        token = html.split('name="csrf_token" value="')[1].split('"')[0]
        client.post("/login", data={"username": "bench", "password": "benchmark-pass", "csrf_token": token})
        for name, size, _ in WORKLOADS[2:]:
            n = repeats_for(size, quick)
            for c in CIPHERS:
                url = f"/documents/{ids[name]}/download?cipher={c}"
                s = summarise(time_ns(lambda: client.get(url).get_data(), n, warmup=2))
                rows.append({"workload": name, "bytes": size, "cipher": c, **s})
    return rows


def environment() -> dict:
    cpu = platform.processor()
    flags = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name") and not cpu.strip():
                cpu = line.split(":", 1)[1].strip()
            if line.startswith("flags"):
                flags = line
                break
    except OSError:
        pass
    ac = [p.read_text().strip() for p in Path("/sys/class/power_supply").glob("A*/online")]
    return {
        "cpu": cpu, "aes_ni": " aes " in flags, "cores": os.cpu_count(),
        "power": {"1": "mains", "0": "battery"}.get(ac[0], "unknown") if ac else "unknown",
        "os": platform.platform(), "python": platform.python_version(), "pycryptodome": Crypto.__version__,
        "date": time.strftime("%Y-%m-%d %H:%M"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="few repetitions, for a smoke test")
    args = parser.parse_args()

    env = environment()
    print(f"CPU {env['cpu']} | AES-NI {env['aes_ni']} | power {env['power']} | Python {env['python']} | PyCryptodome {env['pycryptodome']}")
    print("cipher benchmark ...")
    cipher_rows = bench_ciphers(args.quick)
    print("login (PBKDF2) ...")
    login = bench_login(args.quick)
    print("end-to-end download ...")
    download_rows = bench_download(args.quick)

    RESULTS_DIR.mkdir(exist_ok=True)
    out = {"environment": env, "quick": args.quick, "ciphers": cipher_rows, "login": login, "download": download_rows}
    (RESULTS_DIR / "results.json").write_text(json.dumps(out, indent=2))
    with open(RESULTS_DIR / "ciphers.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(cipher_rows[0]))
        w.writeheader()
        w.writerows(cipher_rows)
    with open(RESULTS_DIR / "download.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(download_rows[0]))
        w.writeheader()
        w.writerows(download_rows)

    print(f"\nlogin PBKDF2 x{login['iterations']:,}: median {login['median_ms']:.0f} ms")
    print(f"\n{'workload':24s} {'op':8s} " + " ".join(f"{c:>18s}" for c in CIPHERS))
    for name, _, _ in WORKLOADS:
        for op in ("encrypt", "decrypt", "seal", "open"):
            cells = []
            for c in CIPHERS:
                r = next(r for r in cipher_rows if r["workload"] == name and r["cipher"] == c and r["op"] == op)
                cells.append(f"{r['median_ms']:9.3f} ms {r['throughput_MBps']:5.0f}MB/s")
            print(f"{name:24s} {op:8s} " + " ".join(cells))
    print(f"\n{'download (end-to-end)':24s} " + " ".join(f"{c:>12s}" for c in CIPHERS))
    for name, _, _ in WORKLOADS[2:]:
        cells = [f"{next(r for r in download_rows if r['workload'] == name and r['cipher'] == c)['median_ms']:9.2f} ms"
                 for c in CIPHERS]
        print(f"{name:24s} " + " ".join(cells))
    print(f"\nwritten to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
