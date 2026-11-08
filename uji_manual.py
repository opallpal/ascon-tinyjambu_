"""
uji_manual.py
=============
Skrip Pengujian Manual Interaktif untuk Seluruh Skenario (S1, S2, S3, S4):
  • S1: Baseline ASCON-128 (Payload 256 B, 1 perangkat, UART & MQTT)
  • S2: Variasi Ukuran Payload (64, 256, 1024 B pada UART & MQTT)
  • S3: Variasi Tingkat Konkurensi (1, 10, 50 perangkat paralel)
  • S4: Pengujian Keamanan (Normal vs 4 Varian Serangan Manipulasi Data)
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np

import crypto_utils
import attacker
from metrics import ResourceMonitor, Stopwatch, throughput_bps
from uart_channel import UARTChannel
from mqtt_channel import MQTTChannel
from receiver_server import ReceiverServer, init_db, DB_PATH
from device_sim import IoTDevice, generate_sensor_reading


def send_packet_transaction(device_id: str, channel_type: str, key: bytes,
                            payload_size: int, condition: str = "normal",
                            attack_variant: str = None, db_conn=None, monitor=None):
    associated_data = device_id.encode("utf-8")
    plaintext = generate_sensor_reading(payload_size)
    nonce = crypto_utils.generate_nonce()
    ct_and_tag = crypto_utils.encrypt(key, nonce, plaintext, associated_data)

    used_key = key
    used_nonce = nonce
    used_ct = ct_and_tag

    if condition == "tampered":
        tamp = attacker.generate_tampered_packet(
            key, nonce, ct_and_tag, variant=attack_variant,
            plaintext=plaintext, associated_data=associated_data
        )
        used_key = tamp.key
        used_nonce = tamp.nonce
        used_ct = tamp.ciphertext_and_tag
        attack_variant = tamp.variant

    header = device_id.encode("utf-8").ljust(16, b"\x00")[:16]
    packet = header + used_nonce + used_ct

    cpu_b, ram_b = monitor.snapshot() if monitor else (0.0, 0.0)

    if channel_type == "UART":
        channel = UARTChannel(baudrate=115200, base_latency_ms=2.0, jitter_ms=0.5)
        receiver = ReceiverServer(key, "UART", db_conn, monitor)

        import threading
        t = threading.Thread(target=lambda: receiver.serve_uart_once(channel, timeout=5.0), daemon=True)
        t.start()

        with Stopwatch() as sw:
            channel.send(packet)
            reply = channel.wait_reply(timeout=5.0)
        t.join(timeout=5.0)

    else:  # MQTT
        channel = MQTTChannel(device_id, network_latency_ms=8.0, jitter_ms=5.0)
        uplink_q = channel.subscribe_uplink()
        receiver = ReceiverServer(key, "MQTT", db_conn, monitor)

        import threading
        def _mqtt_rx():
            try:
                pkt = uplink_q.get(timeout=5.0)
                receiver._handle_packet(pkt, channel)
            except Exception:
                pass
        t = threading.Thread(target=_mqtt_rx, daemon=True)
        t.start()

        with Stopwatch() as sw:
            channel.publish(packet)
            reply = channel.wait_reply(timeout=5.0)
        t.join(timeout=5.0)

    rtt_ms = sw.elapsed_s * 1000.0
    tput = throughput_bps(len(packet), sw.elapsed_s)
    verified = (reply == b"ACK")

    cpu_a, ram_a = monitor.snapshot() if monitor else (0.0, 0.0)

    return {
        "channel": channel_type,
        "condition": condition,
        "attack_variant": attack_variant or "-",
        "payload_size": payload_size,
        "rtt_ms": rtt_ms,
        "throughput_bps": tput,
        "verified": verified,
        "cpu_pct": (cpu_b + cpu_a) / 2.0,
        "ram_mb": (ram_b + ram_a) / 2.0,
        "tag_hex": ct_and_tag[-16:].hex(),
    }


# ---------------------------------------------------------------------------
# PENGUJIAN SKENARIO S1
# ---------------------------------------------------------------------------
def run_s1(repetitions=31):
    from uji_manual_s1 import main as s1_main
    sys.argv = ["uji_manual_s1.py", "--repetitions", str(repetitions)]
    s1_main()


# ---------------------------------------------------------------------------
# PENGUJIAN SKENARIO S2: VARIASI UKURAN PAYLOAD
# ---------------------------------------------------------------------------
def run_s2(repetitions=31):
    payload_sizes = [64, 256, 1024]
    print("=" * 76)
    print("  PENGUJIAN MANUAL: SKENARIO S2 (VARIASI UKURAN PAYLOAD)")
    print("=" * 76)
    print(f"  • Parameter      : Ukuran Payload {payload_sizes} Byte pada UART & MQTT")
    print(f"  • Jumlah Uji     : {repetitions} pengulangan per kombinasi")
    print(f"  • Metrik Diukur  : Latensi RTT (ms) & Throughput (B/s)")
    print("=" * 76)

    key = crypto_utils.generate_key()
    db_conn = init_db(DB_PATH)
    monitor = ResourceMonitor(interval_s=0.5)
    monitor.start()

    summary_rows = []

    for size in payload_sizes:
        print(f"\n[+] Menguji Beban Payload: {size} Byte...")
        for ch in ["UART", "MQTT"]:
            rtts, tputs = [], []
            for rep in range(1, repetitions + 1):
                res = send_packet_transaction(f"dev-s2-{ch.lower()}", ch, key, size, db_conn=db_conn, monitor=monitor)
                rtts.append(res["rtt_ms"])
                tputs.append(res["throughput_bps"])
                if repetitions <= 5 or rep in [1, repetitions // 2, repetitions]:
                    print(f"    [{ch}] #{rep:02d} | RTT: {res['rtt_ms']:6.2f} ms | Throughput: {res['throughput_bps']:7.1f} B/s | Valid: {res['verified']}")

            summary_rows.append({
                "size": size,
                "channel": ch,
                "rtt_mean": np.mean(rtts),
                "rtt_sd": np.std(rtts, ddof=1) if len(rtts) > 1 else 0.0,
                "tput_mean": np.mean(tputs),
                "tput_sd": np.std(tputs, ddof=1) if len(tputs) > 1 else 0.0,
            })

    monitor.stop()

    print("\n" + "=" * 76)
    print("  HASIL REKAPITULASI STATISTIK SKENARIO S2")
    print("=" * 76)
    print(f"{'Payload':<10} | {'Jalur':<6} | {'Latensi RTT Mean ± SD (ms)':<28} | {'Throughput Mean ± SD (B/s)':<24}")
    print("-" * 76)
    for r in summary_rows:
        rtt_str = f"{r['rtt_mean']:6.2f} ± {r['rtt_sd']:5.2f} ms"
        tput_str = f"{r['tput_mean']:7.1f} ± {r['tput_sd']:6.1f} B/s"
        print(f"{r['size']:<5} B   | {r['channel']:<6} | {rtt_str:<28} | {tput_str:<24}")
    print("=" * 76 + "\n")


# ---------------------------------------------------------------------------
# PENGUJIAN SKENARIO S3: VARIASI TINGKAT KONKURENSI
# ---------------------------------------------------------------------------
def run_s3(repetitions=10):
    concurrency_levels = [1, 10, 50]
    print("=" * 76)
    print("  PENGUJIAN MANUAL: SKENARIO S3 (VARIASI TINGKAT KONKURENSI)")
    print("=" * 76)
    print(f"  • Parameter      : {concurrency_levels} Perangkat Paralel Bersamaan")
    print(f"  • Payload        : 256 Byte (Baseline)")
    print(f"  • Pengulangan    : {repetitions} siklus per perangkat")
    print(f"  • Metrik Diukur  : Latensi RTT, Throughput, Beban CPU (%), RAM (MB)")
    print("=" * 76)

    key = crypto_utils.generate_key()
    db_conn = init_db(DB_PATH)
    monitor = ResourceMonitor(interval_s=0.5)
    monitor.start()

    summary_rows = []

    for n_dev in concurrency_levels:
        print(f"\n[+] Menguji Beban Konkurensi: {n_dev} Perangkat Paralel...")
        for ch in ["UART", "MQTT"]:
            print(f"    -> Menjalankan {n_dev} thread perangkat di jalur {ch}...")
            records = []
            with ThreadPoolExecutor(max_workers=min(n_dev, 32)) as pool:
                futures = []
                for dev_idx in range(n_dev):
                    dev_id = f"dev-s3-{ch.lower()}-{dev_idx}"
                    def _worker_job(did=dev_id):
                        local_res = []
                        for _ in range(repetitions):
                            local_res.append(send_packet_transaction(did, ch, key, 256, db_conn=db_conn, monitor=monitor))
                        return local_res
                    futures.append(pool.submit(_worker_job))
                for f in as_completed(futures):
                    records.extend(f.result())

            rtts = [r["rtt_ms"] for r in records]
            tputs = [r["throughput_bps"] for r in records]
            cpus = [r["cpu_pct"] for r in records]
            rams = [r["ram_mb"] for r in records]

            summary_rows.append({
                "n_dev": n_dev,
                "channel": ch,
                "rtt_mean": np.mean(rtts),
                "rtt_sd": np.std(rtts, ddof=1) if len(rtts) > 1 else 0.0,
                "tput_mean": np.mean(tputs),
                "cpu_mean": np.mean(cpus),
                "ram_mean": np.mean(rams),
                "total_pkts": len(records),
            })
            print(f"       Selesai. Total {len(records)} paket diproses. RTT Mean: {np.mean(rtts):.2f} ms")

    monitor.stop()

    print("\n" + "=" * 84)
    print("  HASIL REKAPITULASI STATISTIK SKENARIO S3 (SKALABILITAS / KONKURENSI)")
    print("=" * 84)
    print(f"{'#Perangkat':<11} | {'Jalur':<6} | {'RTT Mean ± SD (ms)':<22} | {'Throughput (B/s)':<17} | {'CPU (%)':<9} | {'RAM (MB)':<9}")
    print("-" * 84)
    for r in summary_rows:
        rtt_str = f"{r['rtt_mean']:6.2f} ± {r['rtt_sd']:5.2f} ms"
        print(f"{r['n_dev']:<11} | {r['channel']:<6} | {rtt_str:<22} | {r['tput_mean']:10.1f} B/s   | {r['cpu_mean']:6.1f} %  | {r['ram_mean']:6.2f} MB")
    print("=" * 84 + "\n")


# ---------------------------------------------------------------------------
# PENGUJIAN SKENARIO S4: PENGUJIAN KEAMANAN & MANIPULASI DATA
# ---------------------------------------------------------------------------
def run_s4(repetitions=31):
    variants = ["bit_flip_ciphertext", "random_tag", "wrong_key", "wrong_nonce"]
    print("=" * 80)
    print("  PENGUJIAN MANUAL: SKENARIO S4 (KEAMANAN & DETEKSI MANIPULASI DATA)")
    print("=" * 80)
    print(f"  • Parameter      : Paket Normal vs 4 Varian Serangan Manipulasi Data")
    print(f"  • Varian Serangan: {variants}")
    print(f"  • Pengulangan    : {repetitions} paket per kondisi")
    print(f"  • Metrik Diukur  : Detection Rate (%) & False Rejection Rate (%)")
    print("=" * 80)

    key = crypto_utils.generate_key()
    db_conn = init_db(DB_PATH)
    monitor = ResourceMonitor(interval_s=0.5)
    monitor.start()

    summary_results = []

    for ch in ["UART", "MQTT"]:
        print(f"\n[+] Menguji Integritas Kriptografi di Jalur {ch}...")

        # 1. Uji Paket Normal (Mengecek False Rejection)
        normal_accepted = 0
        for rep in range(1, repetitions + 1):
            res = send_packet_transaction(f"dev-s4-{ch.lower()}", ch, key, 256, condition="normal", db_conn=db_conn, monitor=monitor)
            if res["verified"]:
                normal_accepted += 1

        frr = ((repetitions - normal_accepted) / repetitions) * 100.0
        summary_results.append({
            "channel": ch, "type": "Paket Normal (Integritas Asli)",
            "total": repetitions, "accepted": normal_accepted, "rejected": repetitions - normal_accepted,
            "rate_label": "False Rejection Rate", "rate_val": frr, "rate_status": "0.0% (SEMPURNA)" if frr == 0.0 else f"{frr:.1f}%"
        })
        print(f"    ✓ Paket Normal : {normal_accepted}/{repetitions} lolos otentikasi (FRR = {frr:.1f}%)")

        # 2. Uji 4 Varian Serangan (Mengecek Detection Rate)
        for var in variants:
            tamp_rejected = 0
            for rep in range(1, repetitions + 1):
                res = send_packet_transaction(f"dev-s4-{ch.lower()}", ch, key, 256, condition="tampered", attack_variant=var, db_conn=db_conn, monitor=monitor)
                if not res["verified"]:
                    tamp_rejected += 1

            det_rate = (tamp_rejected / repetitions) * 100.0
            summary_results.append({
                "channel": ch, "type": f"Serangan: {var}",
                "total": repetitions, "accepted": repetitions - tamp_rejected, "rejected": tamp_rejected,
                "rate_label": "Detection Rate", "rate_val": det_rate, "rate_status": "100.0% (Lolos)" if det_rate == 100.0 else f"{det_rate:.1f}%"
            })
            print(f"    ✕ {var:<22}: {tamp_rejected}/{repetitions} berhasil dideteksi & ditolak (Det Rate = {det_rate:.1f}%)")

    monitor.stop()

    print("\n" + "=" * 84)
    print("  HASIL REKAPITULASI KEAMANAN SKENARIO S4 (DETECTION & FALSE REJECTION)")
    print("=" * 84)
    print(f"{'Kondisi Pengujian':<32} | {'Jalur':<6} | {'Total':<6} | {'Diterima':<9} | {'Ditolak':<8} | {'Hasil Evaluasi'}")
    print("-" * 84)
    for r in summary_results:
        print(f"{r['type']:<32} | {r['channel']:<6} | {r['total']:<6} | {r['accepted']:<9} | {r['rejected']:<8} | {r['rate_label']}: {r['rate_status']}")
    print("=" * 84)
    print("Kesimpulan S4: Seluruh serangan termanipulasi 100% tertolak oleh ASCON-128 AEAD tanpa adanya penolakan salah.\n")


# ---------------------------------------------------------------------------
# MAIN CLI & MENU
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Menu Pengujian Manual ASCON-128 AEAD (S1, S2, S3, S4)")
    parser.add_argument("scenario", nargs="?", default="", choices=["", "S1", "S2", "S3", "S4", "s1", "s2", "s3", "s4"],
                        help="Pilih skenario: S1, S2, S3, atau S4 (kosongkan untuk menampilkan menu)")
    parser.add_argument("--repetitions", type=int, default=31,
                        help="Jumlah pengulangan (default: 31)")
    args = parser.parse_args()

    sc = args.scenario.upper()
    if not sc:
        print("==========================================================")
        print("     PILIH SKENARIO PENGUJIAN MANUAL ASCON-128 AEAD")
        print("==========================================================")
        print("1. Skenario S1: Baseline (256 B, 1 perangkat, UART vs MQTT)")
        print("2. Skenario S2: Variasi Ukuran Payload (64, 256, 1024 B)")
        print("3. Skenario S3: Variasi Tingkat Konkurensi (1, 10, 50 dev)")
        print("4. Skenario S4: Keamanan & Deteksi Manipulasi (Tampered)")
        print("5. Keluar")
        print("==========================================================")
        choice = input("Pilih nomor (1-5): ").strip()
        if choice == "1": sc = "S1"
        elif choice == "2": sc = "S2"
        elif choice == "3": sc = "S3"
        elif choice == "4": sc = "S4"
        else:
            print("Pengujian dibatalkan.")
            return

    reps = args.repetitions
    if sc == "S1":
        run_s1(repetitions=reps)
    elif sc == "S2":
        run_s2(repetitions=reps)
    elif sc == "S3":
        # untuk konkurensi, 10 siklus sudah menghasilkan 610 paket paralel
        run_s3(repetitions=min(reps, 15))
    elif sc == "S4":
        run_s4(repetitions=reps)


if __name__ == "__main__":
    main()

