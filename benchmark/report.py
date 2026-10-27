# PROJECT, 2026
# info_security
# File description:
# Save benchmark results (JSON, CSV) and print summary tables.

"""Save benchmark results (JSON, CSV) and print summary tables."""

import csv
import json
from pathlib import Path

from workloads import FILE_WORKLOADS, WORKLOADS

from hrvault.crypto import CIPHERS

RESULTS_DIR = Path(__file__).resolve().parent / "results"
OPERATIONS = ("encrypt", "decrypt", "seal", "open")


def _write_csv(path: Path, rows: list[dict]) -> None:
    """Write rows of identical dicts as a CSV file with a header."""
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def save_results(results: dict) -> Path:
    """Write results.json, ciphers.csv and download.csv; return the dir."""
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "results.json").write_text(json.dumps(results, indent=2))
    _write_csv(RESULTS_DIR / "ciphers.csv", results["ciphers"])
    _write_csv(RESULTS_DIR / "download.csv", results["download"])
    return RESULTS_DIR


def _find(rows: list[dict], **criteria) -> dict:
    """The first row whose fields match all the given values."""
    return next(row for row in rows
                if all(row[key] == value for key, value in criteria.items()))


def print_ciphers(rows: list[dict]) -> None:
    """Median time and throughput per workload, operation and cipher."""
    print(f"\n{'workload':24s} {'op':8s} "
          + " ".join(f"{cipher:>18s}" for cipher in CIPHERS))
    for name, _, _ in WORKLOADS:
        for op in OPERATIONS:
            cells = [_find(rows, workload=name, cipher=cipher, op=op)
                     for cipher in CIPHERS]
            print(f"{name:24s} {op:8s} " + " ".join(
                f"{row['median_ms']:9.3f} ms {row['throughput_MBps']:5.0f}"
                "MB/s" for row in cells))


def print_downloads(rows: list[dict]) -> None:
    """Median end-to-end download time per file workload and cipher."""
    print(f"\n{'download (end-to-end)':24s} "
          + " ".join(f"{cipher:>12s}" for cipher in CIPHERS))
    for name, _, _ in FILE_WORKLOADS:
        cells = [_find(rows, workload=name, cipher=cipher)["median_ms"]
                 for cipher in CIPHERS]
        print(f"{name:24s} "
              + " ".join(f"{median:9.2f} ms" for median in cells))
