"""
uji_manual_s1.py
================
Skrip pengujian manual khusus untuk Skenario 1 (S1):
Baseline Benchmarking ASCON-128 AEAD
- Parameter: Payload 256 Byte, 1 Perangkat, Jalur UART dan MQTT
- Metrik: Latensi RTT (ms), Throughput (B/s), CPU (%), RAM (MB)
- Standar: 31 Pengulangan (dapat disesuaikan)
"""

import argparse
import os
import sys
import time
import numpy as np

import crypto_utils
from metrics import ResourceMonitor, PacketRecord, Stopwatch, throughput_bps
from uart_channel import UARTChannel
from mqtt_channel import MQTTChannel
from receiver_server import ReceiverServer, init_db, DB_PATH
from device_sim import IoTDevice, generate_sensor_reading


def run_single_packet(device_id: str, channel_type: str, key: bytes,
                      payload_size: int, db_conn, monitor):
    associated_data = device_id.encode("utf-8")
    plaintext = generate_sensor_reading(payload_size)
    nonce = crypto_utils.generate_nonce()
    ct_and_tag = crypto_utils.encrypt(key, nonce, plaintext, associated_data)

    header = device_id.encode("utf-8").ljust(16, b"\x00")[:16]
    packet = header + nonce + ct_and_tag

    cpu_before, ram_before = monitor.snapshot()

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

    cpu_after, ram_after = monitor.snapshot()
    cpu_avg = (cpu_before + cpu_after) / 2.0
    ram_avg = (ram_before + ram_after) / 2.0

    return {
        "channel": channel_type,
        "rtt_ms": rtt_ms,
        "throughput_bps": tput,
        "verified": verified,
        "cpu_pct": cpu_avg,
        "ram_mb": ram_avg,
        "nonce_hex": nonce.hex()[:12] + "...",
        "tag_hex": ct_and_tag[-16:].hex(),
    }


def main():
    parser = argparse.ArgumentParser(description="Uji Manual Skenario S1 (Baseline ASCON-128 AEAD)")
    parser.add_argument("--repetitions", type=int, default=31,
                        help="Jumlah pengulangan per jalur (default: 31 sesuai metodologi statistik)")
    parser.add_argument("--payload", type=int, default=256,
                        help="Ukuran payload dalam byte (default: 256 byte untuk S1)")
    args = parser.parse_args()

    print("=" * 72)
    print("  PENGUJIAN MANUAL: SKENARIO S1 (BASELINE ASCON-128 AEAD)")
    print("=" * 72)
    print(f"  • Parameter      : Payload {args.payload} Byte, 1 Perangkat IoT (ESP32)")
    print(f"  • Jalur Komunikasi: UART (115200 bps) vs MQTT (Broker QoS)")
    print(f"  • Jumlah Pengulangan: {args.repetitions} kali per jalur")
    print(f"  • Algoritma      : ASCON-128 AEAD (Key 128-bit, Nonce 128-bit, Tag 128-bit)")
    print("=" * 72)

    # Inisialisasi
    key = crypto_utils.generate_key()
    db_conn = init_db(DB_PATH)
    monitor = ResourceMonitor(interval_s=0.5)
    monitor.start()

    print("\n[Langkah 1] Pemanasan (Warm-up 3 paket per jalur)...")
    for ch in ["UART", "MQTT"]:
        for _ in range(3):
            run_single_packet("warmup", ch, key, args.payload, db_conn, monitor)
    print("            Warm-up selesai. Sistem dalam kondisi tunak (steady-state).\n")

    results = {"UART": [], "MQTT": []}

    for ch in ["UART", "MQTT"]:
        print("-" * 72)
        print(f"  Memulai Pengujian Jalur: {ch} ({args.repetitions} pengulangan)")
        print("-" * 72)
        print(f"  {'No':<4} | {'Status':<10} | {'RTT (ms)':<10} | {'Throughput (B/s)':<18} | {'Tag ASCON (16B Hex)':<18}")
        print(f"  {'-'*4}-|-{'-'*10}-|-{'-'*10}-|-{'-'*18}-|-{'-'*18}")

        for rep in range(1, args.repetitions + 1):
            res = run_single_packet(f"dev-s1-{ch.lower()}", ch, key, args.payload, db_conn, monitor)
            results[ch].append(res)
            v_str = "✓ VALID" if res["verified"] else "✕ GAGAL"
            print(f"  #{rep:<3} | {v_str:<10} | {res['rtt_ms']:<10.2f} | {res['throughput_bps']:<18.1f} | {res['tag_hex']}")
            time.sleep(0.02)  # jeda mikro agar stabil

    monitor.stop()

    # Hitung Statistik Mean & Standar Deviasi
    print("\n" + "=" * 72)
    print("  HASIL REKAPITULASI STATISTIK SKENARIO S1")
    print("=" * 72)
    print(f"{'Metrik yang Diukur':<25} | {'Jalur UART (Mean ± SD)':<22} | {'Jalur MQTT (Mean ± SD)':<22}")
    print("-" * 72)

    for metric_name, key_name, unit, fmt in [
        ("Latensi RTT", "rtt_ms", "ms", ".2f"),
        ("Throughput", "throughput_bps", "B/s", ".1f"),
        ("Beban CPU", "cpu_pct", "%", ".1f"),
        ("Konsumsi RAM", "ram_mb", "MB", ".2f"),
    ]:
        uart_vals = [r[key_name] for r in results["UART"]]
        mqtt_vals = [r[key_name] for r in results["MQTT"]]

        uart_mean = np.mean(uart_vals)
        uart_sd = np.std(uart_vals, ddof=1)
        mqtt_mean = np.mean(mqtt_vals)
        mqtt_sd = np.std(mqtt_vals, ddof=1)

        uart_str = f"{uart_mean:{fmt}} ± {uart_sd:{fmt}} {unit}"
        mqtt_str = f"{mqtt_mean:{fmt}} ± {mqtt_sd:{fmt}} {unit}"
        print(f"{metric_name:<25} | {uart_str:<22} | {mqtt_str:<22}")

    print("-" * 72)
    print(f"Tingkat Keberhasilan Verifikasi:")
    uart_ok = sum(1 for r in results["UART"] if r["verified"])
    mqtt_ok = sum(1 for r in results["MQTT"] if r["verified"])
    print(f"  • UART : {uart_ok}/{args.repetitions} paket ({uart_ok/args.repetitions*100:.1f}%) lolos otentikasi ASCON")
    print(f"  • MQTT : {mqtt_ok}/{args.repetitions} paket ({mqtt_ok/args.repetitions*100:.1f}%) lolos otentikasi ASCON")
    print("=" * 72)
    print("Data transaksi berhasil disimpan ke basis data SQLite: data/log.sqlite\n")


if __name__ == "__main__":
    main()

