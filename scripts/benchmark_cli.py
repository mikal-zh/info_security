"""
benchmark_cli.py
Automated Command-Line Benchmarking Script.
Evaluates AES-256 (CBC), DES (CBC), and RC4 performance across multiple iterations.
Prints Markdown/ASCII comparative tables and outputs results to CSV.
"""

import sys
import os
import argparse

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src import crypto_manager

def run_cli_benchmark(size_kb: int = 1024, iterations: int = 10, csv_output: str = None):
    print("=" * 80)
    print("INFORMATION SECURITY ASSIGNMENT 1: CRYPTOGRAPHIC BENCHMARK SUITE")
    print("=" * 80)
    print(f"Payload Size: {size_kb} KB ({size_kb * 1024:,} bytes)")
    print(f"Repeated Download/Decryption Iterations: {iterations} runs")
    print("Algorithms: AES-256 (CBC) | DES (CBC) | RC4 (Stream)")
    print("-" * 80)

    # Generate synthetic patterned data
    size_bytes = size_kb * 1024
    pattern = b"GDPR_UU_PDP_SecurityBenchmark_AES_DES_RC4_ITS_2026_"
    data = (pattern * ((size_bytes // len(pattern)) + 1))[:size_bytes]

    print("Running cryptographic operations across iterations...")
    results = crypto_manager.run_benchmark_on_data(data, "benchmark_passphrase_2026", iterations=iterations)
    ciphers = results['ciphers']

    print("\n" + "=" * 90)
    print(f"{'ALGORITHM':<15} | {'MODE':<8} | {'KEY':<7} | {'ORIGINAL':<10} | {'CIPHERTEXT':<11} | {'OVERHEAD':<8} | {'ENTROPY':<7}")
    print("-" * 90)
    for name, c in ciphers.items():
        print(f"{c['algorithm']:<15} | {c['mode']:<8} | {c['key_size_bits']}b{'':<3} | {c['original_size_bytes']:<10} | {c['ciphertext_size_bytes']:<11} | +{c['overhead_bytes']} B{'':<3} | {c['entropy']:<7}")
    print("=" * 90)

    print("\n" + "=" * 105)
    print(f"{'ALGORITHM':<15} | {'ENC AVG':<10} | {'DEC/DL AVG':<12} | {'MIN TIME':<10} | {'MAX TIME':<10} | {'STD DEV':<10} | {'THROUGHPUT':<12}")
    print("-" * 105)
    for name, c in ciphers.items():
        print(
            f"{c['algorithm']:<15} | "
            f"{c['encryption']['avg_ms']:<7.4f} ms | "
            f"{c['decryption']['avg_ms']:<8.4f} ms | "
            f"{c['decryption']['min_ms']:<7.4f} ms | "
            f"{c['decryption']['max_ms']:<7.4f} ms | "
            f"±{c['decryption']['std_dev_ms']:<6.4f} ms | "
            f"{c['dec_throughput_mb_s']:<8.2f} MB/s"
        )
    print("=" * 105)

    if csv_output:
        import csv
        output_dir = os.path.dirname(os.path.abspath(csv_output))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(csv_output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Algorithm', 'Mode', 'Key_Bits', 'Original_Bytes', 'Ciphertext_Bytes',
                'Overhead_Bytes', 'Entropy', 'Enc_Avg_ms', 'Dec_Avg_ms', 'Dec_Min_ms',
                'Dec_Max_ms', 'Dec_StdDev_ms', 'Throughput_MB_s'
            ])
            for name, c in ciphers.items():
                writer.writerow([
                    c['algorithm'], c['mode'], c['key_size_bits'], c['original_size_bytes'],
                    c['ciphertext_size_bytes'], c['overhead_bytes'], c['entropy'],
                    c['encryption']['avg_ms'], c['decryption']['avg_ms'], c['decryption']['min_ms'],
                    c['decryption']['max_ms'], c['decryption']['std_dev_ms'], c['dec_throughput_mb_s']
                ])
        print(f"\n[OK] Benchmark metrics successfully saved to '{csv_output}'.")

if __name__ == '__main__':
    default_csv = os.path.join(BASE_DIR, "output", "benchmark_results.csv")
    parser = argparse.ArgumentParser(description="CLI Benchmark for AES, DES, and RC4")
    parser.add_argument('--size', type=int, default=1024, help="Payload size in KB (default: 1024 KB = 1 MB)")
    parser.add_argument('--iterations', type=int, default=10, help="Download iterations (default: 10)")
    parser.add_argument('--csv', type=str, default=default_csv, help="CSV output filepath")
    args = parser.parse_args()

    run_cli_benchmark(size_kb=args.size, iterations=args.iterations, csv_output=args.csv)

