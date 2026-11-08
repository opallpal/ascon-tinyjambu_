"""
run_benchmark.py
==================
Orkestrator utama simulasi benchmarking ASCON-128 AEAD pada beban kerja IoT.
Menjalankan lima fase sesuai rancangan (Bab 3 dokumen kerangka):
    3.1 Inisialisasi
    3.2 Pemanasan (warm-up, hasil dibuang)
    3.3 Pengujian Performa (S1 baseline, S2 variasi payload, S3 variasi konkurensi)
    3.4 Pengujian Keamanan (S4 normal vs tampered)
    3.5 Analisis (lihat analyze.py)

Jalankan:
    python3 run_benchmark.py                 # menjalankan seluruh skenario (31 pengulangan)
    python3 run_benchmark.py --repetitions 5  # versi cepat utk uji-coba
"""

import argparse
import csv
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

import crypto_utils
from uart_channel import UARTChannel
from mqtt_channel import MQTTChannel, _InMemoryBroker
from receiver_server import ReceiverServer, init_db, DB_PATH
from device_sim import IoTDevice
from metrics import ResourceMonitor, PacketRecord

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
PAYLOAD_SIZES_S2 = [64, 256, 1024]
CONCURRENCY_LEVELS_S3 = [1, 10, 50]
BASELINE_PAYLOAD = 256


# ---------------------------------------------------------------------------
# Fase 3.1 — Inisialisasi
# ---------------------------------------------------------------------------

def initialize_session():
    print("[FASE 1] Inisialisasi: memuat kunci & nonce awal, menyiapkan basis data, "
          "mengaktifkan pemantauan sumber daya...")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    key = crypto_utils.generate_key()  # dimuat sekali & konsisten sepanjang sesi
    db_conn = init_db(DB_PATH)
    monitor = ResourceMonitor(interval_s=1.0)
    monitor.start()
    return key, db_conn, monitor


# ---------------------------------------------------------------------------
# Infrastruktur pengiriman satu paket end-to-end (dipakai semua skenario)
# ---------------------------------------------------------------------------

def _run_uart_transaction(device: IoTDevice, receiver: ReceiverServer, **kwargs) -> PacketRecord:
    """Untuk UART: jalankan receiver di thread terpisah sebelum device
    mengirim, agar receive() tidak memblokir pengiriman."""
    channel: UARTChannel = device.channel
    result_holder = {}

    def _receiver_job():
        result_holder["ok"] = receiver.serve_uart_once(channel, timeout=5.0)

    t = threading.Thread(target=_receiver_job, daemon=True)
    t.start()
    record = device.send_packet(**kwargs)
    t.join(timeout=5.0)
    return record


def _run_mqtt_transaction(device: IoTDevice, receiver: ReceiverServer,
                           uplink_queue, **kwargs) -> PacketRecord:
    channel: MQTTChannel = device.channel
    result_holder = {}

    def _receiver_job():
        try:
            packet = uplink_queue.get(timeout=5.0)
        except Exception:
            return
        receiver._handle_packet(packet, channel)

    t = threading.Thread(target=_receiver_job, daemon=True)
    t.start()
    record = device.send_packet(**kwargs)
    t.join(timeout=5.0)
    return record


def make_device_and_receiver(device_id: str, channel_type: str, key: bytes,
                              resource_monitor: ResourceMonitor):
    if channel_type == "UART":
        channel = UARTChannel(baudrate=115200, base_latency_ms=2.0, jitter_ms=0.5)
        receiver = ReceiverServer(key, "UART", db_conn_global, resource_monitor)
        return channel, receiver, None
    elif channel_type == "MQTT":
        channel = MQTTChannel(device_id, network_latency_ms=8.0, jitter_ms=5.0)
        uplink_queue = channel.subscribe_uplink()
        receiver = ReceiverServer(key, "MQTT", db_conn_global, resource_monitor)
        return channel, receiver, uplink_queue
    raise ValueError(channel_type)


def send_one(device_id: str, channel_type: str, key: bytes, resource_monitor,
             scenario: str, payload_size: int, n_devices: int, repetition: int,
             condition: str = "normal", attack_variant: str = None) -> PacketRecord:
    channel, receiver, uplink_queue = make_device_and_receiver(
        device_id, channel_type, key, resource_monitor)
    device = IoTDevice(device_id, key, channel, channel_type, resource_monitor)
    kwargs = dict(scenario=scenario, payload_size=payload_size, n_devices=n_devices,
                  repetition=repetition, condition=condition, attack_variant=attack_variant)
    if channel_type == "UART":
        return _run_uart_transaction(device, receiver, **kwargs)
    else:
        return _run_mqtt_transaction(device, receiver, uplink_queue, **kwargs)


# ---------------------------------------------------------------------------
# Fase 3.2 — Pemanasan
# ---------------------------------------------------------------------------

def warmup_phase(key: bytes, monitor: ResourceMonitor, n_requests: int = 5):
    print(f"[FASE 2] Pemanasan: mengirim {n_requests} permintaan awal per jalur "
          f"komunikasi (hasil TIDAK diikutsertakan dalam analisis)...")
    for channel_type in ["UART", "MQTT"]:
        for i in range(n_requests):
            send_one(f"warmup-{channel_type}", channel_type, key, monitor,
                      scenario="warmup", payload_size=BASELINE_PAYLOAD,
                      n_devices=1, repetition=i)
    print("[FASE 2] Selesai. Sistem dianggap mencapai kondisi tunak.")


# ---------------------------------------------------------------------------
# Fase 3.3 — Pengujian Performa (S1, S2, S3)
# ---------------------------------------------------------------------------

def scenario_S1_baseline(key, monitor, repetitions, writer):
    print(f"[S1] Baseline benchmarking ASCON (payload {BASELINE_PAYLOAD} byte, "
          f"1 perangkat, UART & MQTT, {repetitions} pengulangan)...")
    for channel_type in ["UART", "MQTT"]:
        for rep in range(repetitions):
            rec = send_one("dev-s1", channel_type, key, monitor, "S1",
                            BASELINE_PAYLOAD, 1, rep)
            writer.writerow(asdict(rec))


def scenario_S2_payload_variation(key, monitor, repetitions, writer):
    print(f"[S2] Variasi ukuran payload {PAYLOAD_SIZES_S2} byte pada kedua jalur "
          f"komunikasi ({repetitions} pengulangan per kombinasi)...")
    for channel_type in ["UART", "MQTT"]:
        for size in PAYLOAD_SIZES_S2:
            for rep in range(repetitions):
                rec = send_one("dev-s2", channel_type, key, monitor, "S2",
                                size, 1, rep)
                writer.writerow(asdict(rec))


def scenario_S3_concurrency(key, monitor, repetitions, writer):
    print(f"[S3] Variasi tingkat konkurensi {CONCURRENCY_LEVELS_S3} perangkat paralel "
          f"pada kedua jalur komunikasi...")
    for channel_type in ["UART", "MQTT"]:
        for n_devices in CONCURRENCY_LEVELS_S3:
            print(f"    -> {channel_type}, {n_devices} perangkat paralel")
            records = []
            with ThreadPoolExecutor(max_workers=min(n_devices, 64)) as pool:
                futures = []
                for dev_idx in range(n_devices):
                    device_id = f"dev-s3-{channel_type}-{dev_idx}"

                    def _job(device_id=device_id):
                        results = []
                        for rep in range(repetitions):
                            rec = send_one(device_id, channel_type, key, monitor, "S3",
                                            BASELINE_PAYLOAD, n_devices, rep)
                            results.append(rec)
                        return results

                    futures.append(pool.submit(_job))
                for fut in as_completed(futures):
                    records.extend(fut.result())
            for rec in records:
                writer.writerow(asdict(rec))


# ---------------------------------------------------------------------------
# Fase 3.4 — Pengujian Keamanan (S4)
# ---------------------------------------------------------------------------

def scenario_S4_security(key, monitor, repetitions, writer):
    from attacker import ATTACK_VARIANTS
    print(f"[S4] Simulasi manipulasi data (normal vs tampered): {ATTACK_VARIANTS} "
          f"pada kedua jalur komunikasi ({repetitions} pengulangan per kondisi)...")
    for channel_type in ["UART", "MQTT"]:
        # kondisi normal
        for rep in range(repetitions):
            rec = send_one("dev-s4", channel_type, key, monitor, "S4",
                            BASELINE_PAYLOAD, 1, rep, condition="normal")
            writer.writerow(asdict(rec))
        # kondisi tampered, tiap varian serangan
        for variant in ATTACK_VARIANTS:
            for rep in range(repetitions):
                rec = send_one("dev-s4", channel_type, key, monitor, "S4",
                                BASELINE_PAYLOAD, 1, rep, condition="tampered",
                                attack_variant=variant)
                writer.writerow(asdict(rec))


# ---------------------------------------------------------------------------
# Program utama
# ---------------------------------------------------------------------------

db_conn_global = None


def main():
    global db_conn_global
    parser = argparse.ArgumentParser(description="Benchmark ASCON-128 AEAD pada beban kerja IoT")
    parser.add_argument("--scenario", type=str, default="ALL",
                        choices=["ALL", "S1", "S2", "S3", "S4"],
                        help="Pilih skenario spesifik: S1, S2, S3, S4, atau ALL (default: ALL)")
    parser.add_argument("--verbose", action="store_true",
                        help="Tampilkan rincian tiap paket ke konsol")
    args = parser.parse_args()

    t_start = time.time()
    key, db_conn, monitor = initialize_session()
    db_conn_global = db_conn

    warmup_phase(key, monitor, args.warmup)

    csv_path = os.path.join(RESULTS_DIR, "benchmark_results.csv")
    fieldnames = list(PacketRecord.__dataclass_fields__.keys())
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        if args.scenario in ["ALL", "S1"]:
            print("[FASE 3] Pengujian performa Baseline (S1)...")
            scenario_S1_baseline(key, monitor, args.repetitions, writer)

        if args.scenario in ["ALL", "S2"]:
            print("[FASE 3] Pengujian performa Variasi Payload (S2)...")
            scenario_S2_payload_variation(key, monitor, args.repetitions, writer)

        if args.scenario in ["ALL", "S3"]:
            print("[FASE 3] Pengujian performa Variasi Konkurensi (S3)...")
            scenario_S3_concurrency(key, monitor, args.repetitions, writer)

        if args.scenario in ["ALL", "S4"]:
            print("[FASE 4] Pengujian keamanan (S4)...")
            scenario_S4_security(key, monitor, args.repetitions, writer)

    monitor.stop()
    db_conn.commit()

    elapsed = time.time() - t_start
    print(f"\n[SELESAI] Pengujian skenario {args.scenario} selesai dalam {elapsed:.1f} detik.")
    print(f"          Hasil mentah: {csv_path}")
    print(f"          Log SQLite : {DB_PATH}")
    print("[FASE 5] Jalankan `python3 analyze.py` untuk menghasilkan statistik "
          "deskriptif, tabel, dan grafik.")


if __name__ == "__main__":
    main()
