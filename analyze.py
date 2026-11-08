"""
analyze.py
===========
Fase 3.5 — Analisis. Mengolah berkas hasil pengujian (results/benchmark_results.csv)
menjadi statistik deskriptif (mean, standard deviation, confidence interval 95%),
tabel ringkasan (CSV), dan grafik perbandingan (PNG) untuk setiap jalur komunikasi
dan setiap tingkatan ukuran payload / konkurensi, serta ringkasan keberhasilan
deteksi manipulasi data (S4). Hasil ringkasan JSON juga ditulis untuk dashboard.
"""

import json
import os

import numpy as np
import pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
CSV_PATH = os.path.join(RESULTS_DIR, "benchmark_results.csv")
FIG_DIR = os.path.join(RESULTS_DIR, "figures")
SUMMARY_JSON = os.path.join(RESULTS_DIR, "summary.json")


def mean_sd_ci(series: pd.Series, confidence: float = 0.95):
    """Menghitung mean, standard deviation (sampel), dan lebar confidence
    interval (metode distribusi-t) untuk sebuah seri data numerik."""
    n = len(series)
    if n == 0:
        return {"mean": None, "sd": None, "ci95_low": None, "ci95_high": None, "n": 0}
    mean = float(series.mean())
    sd = float(series.std(ddof=1)) if n > 1 else 0.0
    if n > 1 and sd > 0:
        se = sd / np.sqrt(n)
        t_crit = stats.t.ppf((1 + confidence) / 2.0, df=n - 1)
        margin = t_crit * se
    else:
        margin = 0.0
    return {
        "mean": mean, "sd": sd,
        "ci95_low": mean - margin, "ci95_high": mean + margin,
        "n": n,
    }


def load_results() -> pd.DataFrame:
    df = pd.read_csv(CSV_PATH)
    return df


# ---------------------------------------------------------------------------
# S1 & S2 — statistik performa per jalur komunikasi & ukuran payload
# ---------------------------------------------------------------------------

def analyze_performance(df: pd.DataFrame):
    perf_df = df[df["scenario"].isin(["S1", "S2"]) & (df["condition"] == "normal")]
    rows = []
    for (channel, size), group in perf_df.groupby(["channel", "payload_size"]):
        rtt_stats = mean_sd_ci(group["rtt_ms"])
        tput_stats = mean_sd_ci(group["throughput_bps"])
        cpu_stats = mean_sd_ci(group["cpu_percent_sender"])
        ram_stats = mean_sd_ci(group["ram_mb_sender"])
        rows.append({
            "channel": channel, "payload_size": size,
            "rtt_ms_mean": rtt_stats["mean"], "rtt_ms_sd": rtt_stats["sd"],
            "rtt_ms_ci95_low": rtt_stats["ci95_low"], "rtt_ms_ci95_high": rtt_stats["ci95_high"],
            "throughput_bps_mean": tput_stats["mean"], "throughput_bps_sd": tput_stats["sd"],
            "cpu_percent_mean": cpu_stats["mean"], "cpu_percent_sd": cpu_stats["sd"],
            "ram_mb_mean": ram_stats["mean"], "ram_mb_sd": ram_stats["sd"],
            "n": rtt_stats["n"],
        })
    out = pd.DataFrame(rows).sort_values(["channel", "payload_size"])
    out.to_csv(os.path.join(RESULTS_DIR, "summary_performance_by_payload.csv"), index=False)
    return out


# ---------------------------------------------------------------------------
# S3 — statistik performa per jalur komunikasi & tingkat konkurensi
# ---------------------------------------------------------------------------

def analyze_concurrency(df: pd.DataFrame):
    conc_df = df[(df["scenario"] == "S3") & (df["condition"] == "normal")]
    rows = []
    for (channel, n_devices), group in conc_df.groupby(["channel", "n_devices"]):
        rtt_stats = mean_sd_ci(group["rtt_ms"])
        tput_stats = mean_sd_ci(group["throughput_bps"])
        cpu_stats = mean_sd_ci(group["cpu_percent_sender"])
        ram_stats = mean_sd_ci(group["ram_mb_sender"])
        rows.append({
            "channel": channel, "n_devices": n_devices,
            "rtt_ms_mean": rtt_stats["mean"], "rtt_ms_sd": rtt_stats["sd"],
            "throughput_bps_mean": tput_stats["mean"], "throughput_bps_sd": tput_stats["sd"],
            "cpu_percent_mean": cpu_stats["mean"],
            "ram_mb_mean": ram_stats["mean"],
            "n": rtt_stats["n"],
        })
    out = pd.DataFrame(rows).sort_values(["channel", "n_devices"])
    out.to_csv(os.path.join(RESULTS_DIR, "summary_performance_by_concurrency.csv"), index=False)
    return out


# ---------------------------------------------------------------------------
# S4 — detection rate & false rejection rate
# ---------------------------------------------------------------------------

def analyze_security(df: pd.DataFrame):
    sec_df = df[df["scenario"] == "S4"]
    rows = []
    for channel, group in sec_df.groupby("channel"):
        normal = group[group["condition"] == "normal"]
        tampered = group[group["condition"] == "tampered"]
        n_normal = len(normal)
        n_normal_accepted = int(normal["verified"].sum())
        false_rejection_rate = 1 - (n_normal_accepted / n_normal) if n_normal else None

        n_tampered = len(tampered)
        n_tampered_rejected = int((~tampered["verified"]).sum())
        detection_rate = (n_tampered_rejected / n_tampered) if n_tampered else None

        rows.append({
            "channel": channel,
            "n_normal_packets": n_normal,
            "normal_accepted": n_normal_accepted,
            "false_rejection_rate": false_rejection_rate,
            "n_tampered_packets": n_tampered,
            "tampered_rejected": n_tampered_rejected,
            "detection_rate": detection_rate,
        })

        # rincian per varian serangan
        for variant, vgroup in tampered.groupby("attack_variant"):
            n = len(vgroup)
            rejected = int((~vgroup["verified"]).sum())
            rows.append({
                "channel": channel,
                "n_normal_packets": None, "normal_accepted": None,
                "false_rejection_rate": None,
                "n_tampered_packets": n, "tampered_rejected": rejected,
                "detection_rate": rejected / n if n else None,
                "attack_variant": variant,
            })
    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(RESULTS_DIR, "summary_security.csv"), index=False)
    return out


# ---------------------------------------------------------------------------
# Grafik perbandingan (matplotlib)
# ---------------------------------------------------------------------------

def make_charts(perf_by_payload: pd.DataFrame, perf_by_concurrency: pd.DataFrame,
                 security: pd.DataFrame):
    os.makedirs(FIG_DIR, exist_ok=True)

    # 1. RTT vs ukuran payload, per channel
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for channel, g in perf_by_payload.groupby("channel"):
        g = g.sort_values("payload_size")
        ax.errorbar(g["payload_size"], g["rtt_ms_mean"], yerr=g["rtt_ms_sd"],
                    marker="o", capsize=4, label=channel)
    ax.set_xlabel("Ukuran payload (byte)")
    ax.set_ylabel("RTT rata-rata (ms)")
    ax.set_title("Latensi (RTT) vs Ukuran Payload — ASCON-128 AEAD")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "rtt_vs_payload.png"), dpi=150)
    plt.close(fig)

    # 2. Throughput vs ukuran payload, per channel
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for channel, g in perf_by_payload.groupby("channel"):
        g = g.sort_values("payload_size")
        ax.plot(g["payload_size"], g["throughput_bps_mean"], marker="s", label=channel)
    ax.set_xlabel("Ukuran payload (byte)")
    ax.set_ylabel("Throughput rata-rata (byte/detik)")
    ax.set_title("Throughput vs Ukuran Payload — ASCON-128 AEAD")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "throughput_vs_payload.png"), dpi=150)
    plt.close(fig)

    # 3. RTT vs tingkat konkurensi, per channel
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for channel, g in perf_by_concurrency.groupby("channel"):
        g = g.sort_values("n_devices")
        ax.errorbar(g["n_devices"], g["rtt_ms_mean"], yerr=None,
                    marker="o", capsize=4, label=channel)
    ax.set_xlabel("Jumlah perangkat paralel")
    ax.set_ylabel("RTT rata-rata (ms)")
    ax.set_title("Latensi (RTT) vs Tingkat Konkurensi")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "rtt_vs_concurrency.png"), dpi=150)
    plt.close(fig)

    # 4. CPU & RAM vs tingkat konkurensi, per channel
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for channel, g in perf_by_concurrency.groupby("channel"):
        g = g.sort_values("n_devices")
        axes[0].plot(g["n_devices"], g["cpu_percent_mean"], marker="o", label=channel)
        axes[1].plot(g["n_devices"], g["ram_mb_mean"], marker="o", label=channel)
    axes[0].set_title("Rata-rata Penggunaan CPU (%)")
    axes[0].set_xlabel("Jumlah perangkat paralel")
    axes[0].legend(); axes[0].grid(alpha=0.3)
    axes[1].set_title("Rata-rata Penggunaan RAM (MB)")
    axes[1].set_xlabel("Jumlah perangkat paralel")
    axes[1].legend(); axes[1].grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG_DIR, "cpu_ram_vs_concurrency.png"), dpi=150)
    plt.close(fig)

    # 5. Detection rate & false rejection rate per channel (bar chart)
    main_rows = security[security["attack_variant"].isna()] if "attack_variant" in security else security
    if len(main_rows):
        fig, ax = plt.subplots(figsize=(6, 4.5))
        channels = main_rows["channel"].tolist()
        detection = [v * 100 for v in main_rows["detection_rate"].tolist()]
        false_rej = [v * 100 for v in main_rows["false_rejection_rate"].tolist()]
        x = np.arange(len(channels))
        width = 0.35
        ax.bar(x - width / 2, detection, width, label="Detection rate (%)")
        ax.bar(x + width / 2, false_rej, width, label="False rejection rate (%)")
        ax.set_xticks(x); ax.set_xticklabels(channels)
        ax.set_ylim(0, 110)
        ax.set_ylabel("Persentase (%)")
        ax.set_title("Keandalan Mekanisme Autentikasi ASCON (S4)")
        ax.legend()
        ax.grid(alpha=0.3, axis="y")
        fig.tight_layout()
        fig.savefig(os.path.join(FIG_DIR, "security_detection_rate.png"), dpi=150)
        plt.close(fig)


def write_summary_json(perf_by_payload, perf_by_concurrency, security):
    summary = {
        "performance_by_payload": json.loads(perf_by_payload.to_json(orient="records")),
        "performance_by_concurrency": json.loads(perf_by_concurrency.to_json(orient="records")),
        "security": json.loads(security.to_json(orient="records")),
    }
    with open(SUMMARY_JSON, "w") as f:
        json.dump(summary, f, indent=2)


def main():
    if not os.path.exists(CSV_PATH):
        print(f"[analyze] Berkas hasil tidak ditemukan: {CSV_PATH}. "
              f"Jalankan run_benchmark.py terlebih dahulu.")
        return
    df = load_results()
    print(f"[analyze] Memuat {len(df)} baris hasil pengujian dari {CSV_PATH}")

    perf_by_payload = analyze_performance(df)
    perf_by_concurrency = analyze_concurrency(df)
    security = analyze_security(df)

    make_charts(perf_by_payload, perf_by_concurrency, security)
    write_summary_json(perf_by_payload, perf_by_concurrency, security)

    print("\n=== Ringkasan Performa per Ukuran Payload (S1/S2, kondisi normal) ===")
    print(perf_by_payload.to_string(index=False))
    print("\n=== Ringkasan Performa per Tingkat Konkurensi (S3, kondisi normal) ===")
    print(perf_by_concurrency.to_string(index=False))
    print("\n=== Ringkasan Keamanan (S4): Detection Rate & False Rejection Rate ===")
    print(security.to_string(index=False))

    print(f"\n[analyze] Tabel CSV & grafik PNG tersimpan di: {RESULTS_DIR}")
    print(f"[analyze] Ringkasan JSON (utk dashboard): {SUMMARY_JSON}")


if __name__ == "__main__":
    main()
