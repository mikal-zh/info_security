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


def _matches(row: dict, criteria: dict) -> bool:
    """True when the row has every field value given in `criteria`."""
    for key, value in criteria.items():
        if row[key] != value:
            return False
    return True


def _find(rows: list[dict], criteria: dict) -> dict:
    """The first row matching `criteria`."""
    for row in rows:
        if _matches(row, criteria):
            return row
    raise KeyError(f"no result row for {criteria}")


def _header(title: str, column_width: int) -> str:
    """Table header: the title, then one right-aligned column per cipher."""
    line = title
    for cipher in CIPHERS:
        line += " " + cipher.rjust(column_width)
    return line


def print_ciphers(rows: list[dict]) -> None:
    """Median time and throughput per workload, operation and cipher."""
    print("\n" + _header(f"{'workload':24s} {'op':8s}", 18))
    for name, _, _ in WORKLOADS:
        for op in OPERATIONS:
            line = f"{name:24s} {op:8s}"
            for cipher in CIPHERS:
                criteria = {"workload": name, "cipher": cipher, "op": op}
                row = _find(rows, criteria)
                line += (f" {row['median_ms']:9.3f} ms "
                         f"{row['throughput_MBps']:5.0f}MB/s")
            print(line)


def print_downloads(rows: list[dict]) -> None:
    """Median end-to-end download time per file workload and cipher."""
    print("\n" + _header(f"{'download (end-to-end)':24s}", 12))
    for name, _, _ in FILE_WORKLOADS:
        line = f"{name:24s}"
        for cipher in CIPHERS:
            row = _find(rows, {"workload": name, "cipher": cipher})
            line += f" {row['median_ms']:9.2f} ms"
        print(line)
