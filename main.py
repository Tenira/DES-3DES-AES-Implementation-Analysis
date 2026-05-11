# main.py
#
# Main driver for the custom AES, DES, and 3DES benchmark project.

from demo_output import generate_demo_output
from benchmark import run_benchmarks
from results_analyzer import analyze_results


def main():
    print("\n==============================================")
    print("Custom AES, DES, and 3DES Benchmark Framework")
    print("==============================================\n")

    print("Step 1: Generating encryption/decryption demo output...")
    generate_demo_output()

    print("\nStep 2: Running benchmark trials...")
    run_benchmarks()

    print("\nStep 3: Analyzing benchmark results and generating graphs...")
    analyze_results()

    print("\nProject run complete.")
    print("Check the results/ folder for CSV files and graphs.\n")


if __name__ == "__main__":
    main()