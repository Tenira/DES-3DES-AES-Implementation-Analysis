# results_analyzer.py

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


RESULTS_DIR = "results"

RAW_CSV_FILE = os.path.join(RESULTS_DIR, "raw_timing_results.csv")
SUMMARY_CSV_FILE = os.path.join(RESULTS_DIR, "summary_timing_results.csv")
ENHANCED_RAW_CSV_FILE = os.path.join(RESULTS_DIR, "enhanced_raw_timing_results.csv")

GRAPH_RAW_ENCRYPTION = os.path.join(RESULTS_DIR, "raw_encryption_trial_points.png")
GRAPH_RAW_DECRYPTION = os.path.join(RESULTS_DIR, "raw_decryption_trial_points.png")

GRAPH_MEAN_ENCRYPTION = os.path.join(RESULTS_DIR, "mean_encryption_time_vs_input_size.png")
GRAPH_MEAN_DECRYPTION = os.path.join(RESULTS_DIR, "mean_decryption_time_vs_input_size.png")

GRAPH_ENCRYPTION_STD = os.path.join(RESULTS_DIR, "encryption_std_dev_vs_input_size.png")
GRAPH_DECRYPTION_STD = os.path.join(RESULTS_DIR, "decryption_std_dev_vs_input_size.png")

GRAPH_ENCRYPTION_THROUGHPUT = os.path.join(RESULTS_DIR, "encryption_throughput_vs_input_size.png")
GRAPH_DECRYPTION_THROUGHPUT = os.path.join(RESULTS_DIR, "decryption_throughput_vs_input_size.png")

GRAPH_ENCRYPTION_TIME_PER_BYTE = os.path.join(RESULTS_DIR, "encryption_time_per_byte_vs_input_size.png")
GRAPH_DECRYPTION_TIME_PER_BYTE = os.path.join(RESULTS_DIR, "decryption_time_per_byte_vs_input_size.png")

GRAPH_ENCRYPTION_SPEED_RATIO = os.path.join(RESULTS_DIR, "encryption_speed_ratio_vs_aes.png")
GRAPH_DECRYPTION_SPEED_RATIO = os.path.join(RESULTS_DIR, "decryption_speed_ratio_vs_aes.png")

GRAPH_PADDING_OVERHEAD = os.path.join(RESULTS_DIR, "ciphertext_expansion_vs_input_size.png")

GRAPH_ENCRYPTION_BEST_FIT = os.path.join(RESULTS_DIR, "encryption_scaling_best_fit.png")
GRAPH_DECRYPTION_BEST_FIT = os.path.join(RESULTS_DIR, "decryption_scaling_best_fit.png")

GRAPH_ENCRYPTION_ROLLING_AVERAGE = os.path.join(
    RESULTS_DIR, "encryption_rolling_average_convergence.png"
)
GRAPH_DECRYPTION_ROLLING_AVERAGE = os.path.join(
    RESULTS_DIR, "decryption_rolling_average_convergence.png"
)


def load_raw_results():
    if not os.path.exists(RAW_CSV_FILE):
        raise FileNotFoundError(
            "raw_timing_results.csv not found. Run the benchmark first."
        )

    return pd.read_csv(RAW_CSV_FILE)


def add_raw_metrics(df):
    df = df.copy()

    df["input_size_MB"] = df["input_size_bytes"] / (1024 * 1024)

    df["encryption_throughput_MBps"] = (
        df["input_size_MB"] / df["encryption_time_seconds"]
    )

    df["decryption_throughput_MBps"] = (
        df["input_size_MB"] / df["decryption_time_seconds"]
    )

    df["encryption_time_per_byte"] = (
        df["encryption_time_seconds"] / df["input_size_bytes"]
    )

    df["decryption_time_per_byte"] = (
        df["decryption_time_seconds"] / df["input_size_bytes"]
    )

    df["encryption_ns_per_byte"] = df["encryption_time_per_byte"] * 1_000_000_000
    df["decryption_ns_per_byte"] = df["decryption_time_per_byte"] * 1_000_000_000

    df["ciphertext_expansion_ratio"] = (
        df["ciphertext_size_bytes"] / df["input_size_bytes"]
    )

    return df


def create_summary_table(df):
    grouped = df.groupby(["algorithm", "input_size_bytes", "input_size_MB"])

    summary = grouped.agg(
        mean_encryption_time_seconds=("encryption_time_seconds", "mean"),
        median_encryption_time_seconds=("encryption_time_seconds", "median"),
        std_encryption_time_seconds=("encryption_time_seconds", "std"),
        var_encryption_time_seconds=("encryption_time_seconds", "var"),
        q1_encryption_time_seconds=("encryption_time_seconds", lambda x: x.quantile(0.25)),
        q3_encryption_time_seconds=("encryption_time_seconds", lambda x: x.quantile(0.75)),
        min_encryption_time_seconds=("encryption_time_seconds", "min"),
        max_encryption_time_seconds=("encryption_time_seconds", "max"),

        mean_decryption_time_seconds=("decryption_time_seconds", "mean"),
        median_decryption_time_seconds=("decryption_time_seconds", "median"),
        std_decryption_time_seconds=("decryption_time_seconds", "std"),
        var_decryption_time_seconds=("decryption_time_seconds", "var"),
        q1_decryption_time_seconds=("decryption_time_seconds", lambda x: x.quantile(0.25)),
        q3_decryption_time_seconds=("decryption_time_seconds", lambda x: x.quantile(0.75)),
        min_decryption_time_seconds=("decryption_time_seconds", "min"),
        max_decryption_time_seconds=("decryption_time_seconds", "max"),

        mean_encryption_throughput_MBps=("encryption_throughput_MBps", "mean"),
        mean_decryption_throughput_MBps=("decryption_throughput_MBps", "mean"),

        mean_encryption_ns_per_byte=("encryption_ns_per_byte", "mean"),
        mean_decryption_ns_per_byte=("decryption_ns_per_byte", "mean"),

        mean_ciphertext_expansion_ratio=("ciphertext_expansion_ratio", "mean")
    ).reset_index()

    summary["encryption_coefficient_of_variation"] = (
        summary["std_encryption_time_seconds"] /
        summary["mean_encryption_time_seconds"]
    )

    summary["decryption_coefficient_of_variation"] = (
        summary["std_decryption_time_seconds"] /
        summary["mean_decryption_time_seconds"]
    )

    trial_counts = df.groupby(
        ["algorithm", "input_size_bytes"]
    ).size().reset_index(name="num_trials")

    summary = summary.merge(
        trial_counts,
        on=["algorithm", "input_size_bytes"],
        how="left"
    )

    summary["encryption_95ci_seconds"] = (
        1.96 * summary["std_encryption_time_seconds"] /
        np.sqrt(summary["num_trials"])
    )

    summary["decryption_95ci_seconds"] = (
        1.96 * summary["std_decryption_time_seconds"] /
        np.sqrt(summary["num_trials"])
    )

    summary["encryption_iqr_seconds"] = (
        summary["q3_encryption_time_seconds"] -
        summary["q1_encryption_time_seconds"]
    )

    summary["decryption_iqr_seconds"] = (
        summary["q3_decryption_time_seconds"] -
        summary["q1_decryption_time_seconds"]
    )

    return summary


def add_speed_ratios(summary):
    summary = summary.copy()

    aes_encryption = summary[summary["algorithm"] == "AES"][
        ["input_size_bytes", "mean_encryption_time_seconds"]
    ].rename(columns={
        "mean_encryption_time_seconds": "aes_mean_encryption_time_seconds"
    })

    aes_decryption = summary[summary["algorithm"] == "AES"][
        ["input_size_bytes", "mean_decryption_time_seconds"]
    ].rename(columns={
        "mean_decryption_time_seconds": "aes_mean_decryption_time_seconds"
    })

    summary = summary.merge(aes_encryption, on="input_size_bytes", how="left")
    summary = summary.merge(aes_decryption, on="input_size_bytes", how="left")

    summary["encryption_time_ratio_vs_aes"] = (
        summary["mean_encryption_time_seconds"] /
        summary["aes_mean_encryption_time_seconds"]
    )

    summary["decryption_time_ratio_vs_aes"] = (
        summary["mean_decryption_time_seconds"] /
        summary["aes_mean_decryption_time_seconds"]
    )

    return summary


def plot_raw_trial_points(df, y_column, title, ylabel, output_file):
    plt.figure()

    for algorithm in df["algorithm"].unique():
        subset = df[df["algorithm"] == algorithm]

        plt.scatter(
            subset["input_size_bytes"],
            subset[y_column],
            alpha=0.35,
            label=algorithm
        )

    plt.xlabel("Input Size (bytes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def plot_summary_line(summary, y_column, title, ylabel, output_file):
    plt.figure()

    for algorithm in summary["algorithm"].unique():
        subset = summary[summary["algorithm"] == algorithm]

        plt.plot(
            subset["input_size_bytes"],
            subset[y_column],
            marker="o",
            label=algorithm
        )

    plt.xlabel("Input Size (bytes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def plot_ratio_vs_aes(summary, y_column, title, ylabel, output_file):
    plt.figure()

    for algorithm in summary["algorithm"].unique():
        subset = summary[summary["algorithm"] == algorithm]

        plt.plot(
            subset["input_size_bytes"],
            subset[y_column],
            marker="o",
            label=algorithm
        )

    plt.axhline(y=1.0, linestyle="--", linewidth=1)

    plt.xlabel("Input Size (bytes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def plot_best_fit_scaling(df, y_column, title, ylabel, output_file):
    plt.figure()

    for algorithm in df["algorithm"].unique():
        subset = df[df["algorithm"] == algorithm].copy()

        x = subset["input_size_bytes"].to_numpy()
        y = subset[y_column].to_numpy()

        plt.scatter(
            x,
            y,
            alpha=0.20,
            label=f"{algorithm} trials"
        )

        coefficients = np.polyfit(x, y, 1)
        fit_line = coefficients[0] * x + coefficients[1]

        sorted_indices = np.argsort(x)

        plt.plot(
            x[sorted_indices],
            fit_line[sorted_indices],
            linewidth=2,
            label=f"{algorithm} best fit"
        )

    plt.xlabel("Input Size (bytes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def plot_rolling_average(df, y_column, title, ylabel, output_file):
    plt.figure()

    largest_size = df["input_size_bytes"].max()

    for algorithm in df["algorithm"].unique():
        subset = df[
            (df["algorithm"] == algorithm) &
            (df["input_size_bytes"] == largest_size)
        ].copy()

        subset = subset.sort_values("trial_number")
        subset["rolling_average"] = subset[y_column].expanding().mean()

        plt.plot(
            subset["trial_number"],
            subset["rolling_average"],
            marker="o",
            markersize=3,
            label=algorithm
        )

    plt.xlabel("Trial Number")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def print_summary(summary):
    print("\nSummary Timing Results:\n")

    display_columns = [
        "algorithm",
        "input_size_bytes",
        "num_trials",

        "mean_encryption_time_seconds",
        "median_encryption_time_seconds",
        "std_encryption_time_seconds",
        "var_encryption_time_seconds",
        "encryption_95ci_seconds",
        "encryption_coefficient_of_variation",

        "mean_decryption_time_seconds",
        "median_decryption_time_seconds",
        "std_decryption_time_seconds",
        "var_decryption_time_seconds",
        "decryption_95ci_seconds",
        "decryption_coefficient_of_variation",

        "mean_encryption_throughput_MBps",
        "mean_decryption_throughput_MBps",

        "mean_encryption_ns_per_byte",
        "mean_decryption_ns_per_byte",

        "encryption_time_ratio_vs_aes",
        "decryption_time_ratio_vs_aes",

        "mean_ciphertext_expansion_ratio"
    ]

    display_df = summary[display_columns].copy()

    for column in display_df.columns:
        if column not in ["algorithm", "input_size_bytes", "num_trials"]:
            display_df[column] = display_df[column].map(lambda x: f"{x:.6f}")

    print(display_df.to_string(index=False))


def analyze_results():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    raw_df = load_raw_results()
    enhanced_raw_df = add_raw_metrics(raw_df)

    summary = create_summary_table(enhanced_raw_df)
    summary = add_speed_ratios(summary)

    enhanced_raw_df.to_csv(ENHANCED_RAW_CSV_FILE, index=False)
    summary.to_csv(SUMMARY_CSV_FILE, index=False)

    print_summary(summary)

    plot_raw_trial_points(
        enhanced_raw_df,
        "encryption_time_seconds",
        "Raw Encryption Trial Times vs Input Size",
        "Encryption Time (seconds)",
        GRAPH_RAW_ENCRYPTION
    )

    plot_raw_trial_points(
        enhanced_raw_df,
        "decryption_time_seconds",
        "Raw Decryption Trial Times vs Input Size",
        "Decryption Time (seconds)",
        GRAPH_RAW_DECRYPTION
    )

    plot_summary_line(
        summary,
        "mean_encryption_time_seconds",
        "Mean Encryption Time vs Input Size",
        "Mean Encryption Time (seconds)",
        GRAPH_MEAN_ENCRYPTION
    )

    plot_summary_line(
        summary,
        "mean_decryption_time_seconds",
        "Mean Decryption Time vs Input Size",
        "Mean Decryption Time (seconds)",
        GRAPH_MEAN_DECRYPTION
    )

    plot_summary_line(
        summary,
        "std_encryption_time_seconds",
        "Encryption Timing Variation vs Input Size",
        "Standard Deviation (seconds)",
        GRAPH_ENCRYPTION_STD
    )

    plot_summary_line(
        summary,
        "std_decryption_time_seconds",
        "Decryption Timing Variation vs Input Size",
        "Standard Deviation (seconds)",
        GRAPH_DECRYPTION_STD
    )

    plot_summary_line(
        summary,
        "mean_encryption_throughput_MBps",
        "Mean Encryption Throughput vs Input Size",
        "Throughput (MB/s)",
        GRAPH_ENCRYPTION_THROUGHPUT
    )

    plot_summary_line(
        summary,
        "mean_decryption_throughput_MBps",
        "Mean Decryption Throughput vs Input Size",
        "Throughput (MB/s)",
        GRAPH_DECRYPTION_THROUGHPUT
    )

    plot_summary_line(
        summary,
        "mean_encryption_ns_per_byte",
        "Mean Encryption Time per Byte vs Input Size",
        "Nanoseconds per Byte",
        GRAPH_ENCRYPTION_TIME_PER_BYTE
    )

    plot_summary_line(
        summary,
        "mean_decryption_ns_per_byte",
        "Mean Decryption Time per Byte vs Input Size",
        "Nanoseconds per Byte",
        GRAPH_DECRYPTION_TIME_PER_BYTE
    )

    plot_ratio_vs_aes(
        summary,
        "encryption_time_ratio_vs_aes",
        "Encryption Time Ratio Relative to AES",
        "Ratio Compared to AES",
        GRAPH_ENCRYPTION_SPEED_RATIO
    )

    plot_ratio_vs_aes(
        summary,
        "decryption_time_ratio_vs_aes",
        "Decryption Time Ratio Relative to AES",
        "Ratio Compared to AES",
        GRAPH_DECRYPTION_SPEED_RATIO
    )

    plot_summary_line(
        summary,
        "mean_ciphertext_expansion_ratio",
        "Ciphertext Expansion Ratio vs Input Size",
        "Ciphertext Size / Plaintext Size",
        GRAPH_PADDING_OVERHEAD
    )

    plot_best_fit_scaling(
        enhanced_raw_df,
        "encryption_time_seconds",
        "Raw Encryption Trial Times with Best-Fit Scaling Lines",
        "Encryption Time (seconds)",
        GRAPH_ENCRYPTION_BEST_FIT
    )

    plot_best_fit_scaling(
        enhanced_raw_df,
        "decryption_time_seconds",
        "Raw Decryption Trial Times with Best-Fit Scaling Lines",
        "Decryption Time (seconds)",
        GRAPH_DECRYPTION_BEST_FIT
    )

    plot_rolling_average(
        enhanced_raw_df,
        "encryption_time_seconds",
        "Encryption Rolling Average Convergence at Largest Input Size",
        "Rolling Average Encryption Time (seconds)",
        GRAPH_ENCRYPTION_ROLLING_AVERAGE
    )

    plot_rolling_average(
        enhanced_raw_df,
        "decryption_time_seconds",
        "Decryption Rolling Average Convergence at Largest Input Size",
        "Rolling Average Decryption Time (seconds)",
        GRAPH_DECRYPTION_ROLLING_AVERAGE
    )

    print("\nFiles generated:")
    print(f"  {ENHANCED_RAW_CSV_FILE}")
    print(f"  {SUMMARY_CSV_FILE}")
    print(f"  {GRAPH_RAW_ENCRYPTION}")
    print(f"  {GRAPH_RAW_DECRYPTION}")
    print(f"  {GRAPH_MEAN_ENCRYPTION}")
    print(f"  {GRAPH_MEAN_DECRYPTION}")
    print(f"  {GRAPH_ENCRYPTION_STD}")
    print(f"  {GRAPH_DECRYPTION_STD}")
    print(f"  {GRAPH_ENCRYPTION_THROUGHPUT}")
    print(f"  {GRAPH_DECRYPTION_THROUGHPUT}")
    print(f"  {GRAPH_ENCRYPTION_TIME_PER_BYTE}")
    print(f"  {GRAPH_DECRYPTION_TIME_PER_BYTE}")
    print(f"  {GRAPH_ENCRYPTION_SPEED_RATIO}")
    print(f"  {GRAPH_DECRYPTION_SPEED_RATIO}")
    print(f"  {GRAPH_PADDING_OVERHEAD}")
    print(f"  {GRAPH_ENCRYPTION_BEST_FIT}")
    print(f"  {GRAPH_DECRYPTION_BEST_FIT}")
    print(f"  {GRAPH_ENCRYPTION_ROLLING_AVERAGE}")
    print(f"  {GRAPH_DECRYPTION_ROLLING_AVERAGE}")