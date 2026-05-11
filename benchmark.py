# benchmark.py
#
# Benchmark custom AES, custom DES, and custom 3DES implementations.

import csv
import os
import time

from config import INPUT_SIZES, NUM_TRIALS
from data_generator import generate_application_plaintext

import custom_aes
import custom_des
import custom_3des


RESULTS_DIR = "results"
RAW_RESULTS_FILE = os.path.join(RESULTS_DIR, "raw_timing_results.csv")


# Fixed keys and IVs are used to keep benchmark conditions consistent.
AES_KEY = b"1234567890ABCDEF"          # 16 bytes
AES_IV = b"ABCDEF1234567890"           # 16 bytes

DES_KEY = b"12345678"                  # 8 bytes
DES_IV = b"ABCDEFGH"                   # 8 bytes

TDES_KEY = b"12345678ABCDEFGH87654321" # 24 bytes
TDES_IV = b"HGFEDCBA"                  # 8 bytes


ALGORITHMS = {
    "AES": {
        "encrypt": lambda plaintext: custom_aes.encrypt_cbc(
            plaintext,
            AES_KEY,
            AES_IV
        ),
        "decrypt": lambda ciphertext: custom_aes.decrypt_cbc(
            ciphertext,
            AES_KEY,
            AES_IV
        )
    },
    "DES": {
        "encrypt": lambda plaintext: custom_des.encrypt_cbc(
            plaintext,
            DES_KEY,
            DES_IV
        ),
        "decrypt": lambda ciphertext: custom_des.decrypt_cbc(
            ciphertext,
            DES_KEY,
            DES_IV
        )
    },
    "3DES": {
        "encrypt": lambda plaintext: custom_3des.encrypt_3des_cbc(
            plaintext,
            TDES_KEY,
            TDES_IV
        ),
        "decrypt": lambda ciphertext: custom_3des.decrypt_3des_cbc(
            ciphertext,
            TDES_KEY,
            TDES_IV
        )
    }
}


def benchmark_algorithm(algorithm_name, encrypt_func, decrypt_func, size_bytes):
    trial_results = []

    for trial in range(1, NUM_TRIALS + 1):
        plaintext = generate_application_plaintext(size_bytes)

        start_encrypt = time.perf_counter()
        ciphertext = encrypt_func(plaintext)
        end_encrypt = time.perf_counter()

        start_decrypt = time.perf_counter()
        recovered_plaintext = decrypt_func(ciphertext)
        end_decrypt = time.perf_counter()

        if plaintext != recovered_plaintext:
            raise ValueError(
                f"{algorithm_name} failed correctness check "
                f"for input size {size_bytes} on trial {trial}"
            )

        encryption_time = end_encrypt - start_encrypt
        decryption_time = end_decrypt - start_decrypt

        trial_results.append({
            "algorithm": algorithm_name,
            "input_size_bytes": size_bytes,
            "trial_number": trial,
            "encryption_time_seconds": encryption_time,
            "decryption_time_seconds": decryption_time,
            "ciphertext_size_bytes": len(ciphertext)
        })

    return trial_results


def run_benchmarks():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    all_results = []

    print("\nStarting custom implementation benchmark tests...\n")

    for size_bytes in INPUT_SIZES:
        print(f"Input size: {size_bytes} bytes")

        for algorithm_name, funcs in ALGORITHMS.items():
            print(f"  Testing custom {algorithm_name}...")

            trial_results = benchmark_algorithm(
                algorithm_name,
                funcs["encrypt"],
                funcs["decrypt"],
                size_bytes
            )

            all_results.extend(trial_results)

            avg_encrypt = sum(
                row["encryption_time_seconds"] for row in trial_results
            ) / len(trial_results)

            avg_decrypt = sum(
                row["decryption_time_seconds"] for row in trial_results
            ) / len(trial_results)

            print(
                f"    Avg encryption: {avg_encrypt:.8f} sec | "
                f"Avg decryption: {avg_decrypt:.8f} sec"
            )

        print()

    save_raw_results(all_results)

    print(f"Benchmark complete. Raw results saved to: {RAW_RESULTS_FILE}")


def save_raw_results(results):
    fieldnames = [
        "algorithm",
        "input_size_bytes",
        "trial_number",
        "encryption_time_seconds",
        "decryption_time_seconds",
        "ciphertext_size_bytes"
    ]

    with open(RAW_RESULTS_FILE, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in results:
            writer.writerow(row)
