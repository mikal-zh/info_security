# PROJECT, 2026
# info_security
# File description:
# Benchmark AES-256-CBC, DES-CBC and RC4-drop3072 on onboarding workloads.

"""Benchmark AES-256-CBC, DES-CBC and RC4-drop3072 on the onboarding data.

    python benchmark/run_benchmark.py            # full run (~2 min)
    python benchmark/run_benchmark.py --quick    # smoke test

What is measured and why:
  1. cipher only vs. full envelope (cipher + HMAC-SHA256)
  2. workloads sized like the real onboarding items (workloads.py)
  3. the login cost (PBKDF2), paid once per session
  4. end-to-end download through the Flask app
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import report  # noqa: E402
from cipher_bench import bench_ciphers, bench_login  # noqa: E402
from download_bench import bench_download  # noqa: E402
from environment import environment  # noqa: E402


def parse_args() -> argparse.Namespace:
    """Command-line options."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="few repetitions, for a smoke test")
    return parser.parse_args()


def main():
    """Run every measurement, save the results and print the tables."""
    quick = parse_args().quick
    env = environment()
    print(f"CPU {env['cpu']} | AES-NI {env['aes_ni']} | power "
          f"{env['power']} | Python {env['python']}")
    results = {"environment": env, "quick": quick}
    print("cipher benchmark ...")
    results["ciphers"] = bench_ciphers(quick)
    print("login (PBKDF2) ...")
    results["login"] = bench_login(quick)
    print("end-to-end download ...")
    results["download"] = bench_download(quick)
    folder = report.save_results(results)
    print(f"\nlogin PBKDF2 x{results['login']['iterations']:,}: median "
          f"{results['login']['median_ms']:.0f} ms")
    report.print_ciphers(results["ciphers"])
    report.print_downloads(results["download"])
    print(f"\nwritten to {folder}")


if __name__ == "__main__":
    main()
