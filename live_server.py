"""
live_server.py
==============
Server Backend Real-Time untuk Simulasi & Pemantauan ASCON-128 AEAD.
Menggunakan FastAPI + WebSockets untuk menyiarkan metrik transaksi paket
detik demi detik ke antarmuka web, mendukung kontrol interaktif (Mulai/Jeda,
pemilihan jalur, ukuran data, dan injeksi serangan manipulasi seketika).
"""

import asyncio
import collections
import json
import os
import random
import string
import threading
import time
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import attacker
import crypto_utils
from metrics import ResourceMonitor, Stopwatch, throughput_bps
from mqtt_channel import MQTTChannel
from receiver_server import ReceiverServer, init_db, DB_PATH
from uart_channel import UARTChannel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

app = FastAPI(title="ASCON-128 AEAD Real-Time Benchmark Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# State Simulasi Real-Time & Broadcast Manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    def broadcast_sync(self, message: dict):
        """Menyiarkan pesan JSON ke semua websocket aktif secara aman."""
        data_text = json.dumps(message)
        with self._lock:
            dead = []
            for ws in self.active_connections:
                try:
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(ws.send_text(data_text), loop)
                except Exception:
                    dead.append(ws)
            for d in dead:
                if d in self.active_connections:
                    self.active_connections.remove(d)


manager = ConnectionManager()
loop = None  # diisi saat startup


class SimulationConfig(BaseModel):
    channel: str = "BOTH"  # "UART", "MQTT", "BOTH"
    payload_size: int = 256  # 64, 256, 1024
    delay_ms: int = 350      # jeda antar paket (ms)
    n_devices: int = 1


class AttackRequest(BaseModel):
    variant: str = "bit_flip_ciphertext"  # bit_flip_ciphertext, random_tag, wrong_key, wrong_nonce


class SimulationWorker:
    def __init__(self):
        self.running = False
        self.paused = False
        self.channel_mode = "BOTH"
        self.payload_size = 256
        self.delay_ms = 350
        self.n_devices = 1

        self.key = crypto_utils.generate_key()
        self.db_conn = init_db(DB_PATH)
        self.monitor = ResourceMonitor(interval_s=0.5)
        self.monitor.start()

        self._attack_queue: List[str] = []
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Statistik akumulatif sesi real-time
        self.stats = {
            "total_packets": 0,
            "normal_packets": 0,
            "tampered_packets": 0,
            "accepted_packets": 0,
            "rejected_packets": 0,
            "uart_count": 0,
            "mqtt_count": 0,
            "latest_uart_rtt": 0.0,
            "latest_mqtt_rtt": 0.0,
            "latest_throughput": 0.0,
            "detection_rate_pct": 100.0,
            "false_rejection_rate_pct": 0.0,
        }
        self.recent_packets = collections.deque(maxlen=40)
        self._channel_toggle = False

    def start(self, config: SimulationConfig):
        with self._lock:
            self.channel_mode = config.channel
            self.payload_size = config.payload_size
            self.delay_ms = max(50, config.delay_ms)
            self.n_devices = config.n_devices
            self.paused = False

            if self.running and self._worker_thread and self._worker_thread.is_alive():
                return

            self.running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(target=self._run_loop, daemon=True)
            self._worker_thread.start()

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def stop(self):
        with self._lock:
            self.running = False
            self.paused = False
            self._stop_event.set()

    def reset_stats(self):
        with self._lock:
            self.stats = {
                "total_packets": 0,
                "normal_packets": 0,
                "tampered_packets": 0,
                "accepted_packets": 0,
                "rejected_packets": 0,
                "uart_count": 0,
                "mqtt_count": 0,
                "latest_uart_rtt": 0.0,
                "latest_mqtt_rtt": 0.0,
                "latest_throughput": 0.0,
                "detection_rate_pct": 100.0,
                "false_rejection_rate_pct": 0.0,
            }
            self.recent_packets.clear()

    def queue_attack(self, variant: str):
        with self._lock:
            self._attack_queue.append(variant)

    def _generate_sensor_payload(self, target_size: int) -> bytes:
        reading = {
            "ts": round(time.time(), 3),
            "temp_c": round(random.uniform(21.0, 34.0), 2),
            "hum_pct": round(random.uniform(35.0, 85.0), 2),
            "lux": round(random.uniform(10.0, 950.0), 1),
        }
        base = json.dumps(reading, separators=(",", ":"))
        pad_needed = max(0, target_size - len(base) - len('"pad":""'))
        reading["pad"] = "".join(random.choices(string.ascii_lowercase, k=pad_needed))
        return json.dumps(reading, separators=(",", ":")).encode("utf-8")

    def _run_loop(self):
        while not self._stop_event.is_set():
            if self.paused:
                time.sleep(0.1)
                continue

            # 1. Tentukan kanal
            if self.channel_mode == "UART":
                channel_type = "UART"
            elif self.channel_mode == "MQTT":
                channel_type = "MQTT"
            else:
                channel_type = "UART" if self._channel_toggle else "MQTT"
                self._channel_toggle = not self._channel_toggle

            # 2. Cek apakah ada serangan yang diantrekan
            condition = "normal"
            attack_variant = ""
            with self._lock:
                if self._attack_queue:
                    condition = "tampered"
                    attack_variant = self._attack_queue.pop(0)

            dev_idx = random.randint(1, max(1, self.n_devices))
            device_id = f"ESP32-DEV-{dev_idx:02d}"

            # 3. Jalankan transaksi paket
            self._execute_transaction(device_id, channel_type, condition, attack_variant)

            # Jeda waktu antar paket
            time.sleep(self.delay_ms / 1000.0)

    def _execute_transaction(self, device_id: str, channel_type: str,
                             condition: str, attack_variant: str):
        associated_data = device_id.encode("utf-8")
        plaintext = self._generate_sensor_payload(self.payload_size)
        nonce = crypto_utils.generate_nonce()
        ct_and_tag = crypto_utils.encrypt(self.key, nonce, plaintext, associated_data)

        used_key = self.key
        used_nonce = nonce
        used_ct = ct_and_tag

        if condition == "tampered":
            tampered = attacker.generate_tampered_packet(
                self.key, nonce, ct_and_tag, variant=attack_variant,
                plaintext=plaintext, associated_data=associated_data
            )
            used_key = tampered.key
            used_nonce = tampered.nonce
            used_ct = tampered.ciphertext_and_tag
            attack_variant = tampered.variant

        header = device_id.encode("utf-8").ljust(16, b"\x00")[:16]
        packet = header + used_nonce + used_ct

        # Inisialisasi kanal & receiver
        if channel_type == "UART":
            channel = UARTChannel(baudrate=115200, base_latency_ms=2.0, jitter_ms=0.5)
            receiver = ReceiverServer(self.key, "UART", self.db_conn, self.monitor)

            def _uart_rx():
                receiver.serve_uart_once(channel, timeout=5.0)

            rx_thread = threading.Thread(target=_uart_rx, daemon=True)
            rx_thread.start()

            with Stopwatch() as sw:
                channel.send(packet)
                reply = channel.wait_reply(timeout=5.0)
            rx_thread.join(timeout=5.0)

        else:  # MQTT
            channel = MQTTChannel(device_id, network_latency_ms=8.0, jitter_ms=5.0)
            uplink_q = channel.subscribe_uplink()
            receiver = ReceiverServer(self.key, "MQTT", self.db_conn, self.monitor)

            def _mqtt_rx():
                try:
                    pkt = uplink_q.get(timeout=5.0)
                    receiver._handle_packet(pkt, channel)
                except Exception:
                    pass

            rx_thread = threading.Thread(target=_mqtt_rx, daemon=True)
            rx_thread.start()

            with Stopwatch() as sw:
                channel.publish(packet)
                reply = channel.wait_reply(timeout=5.0)
            rx_thread.join(timeout=5.0)

        rtt_ms = round(sw.elapsed_s * 1000.0, 2)
        tput = round(throughput_bps(len(packet), sw.elapsed_s), 1)
        verified = bool(reply == b"ACK")

        # Snapshot resource
        cpu_pct, ram_mb = self.monitor.snapshot()

        # Update stats
        with self._lock:
            self.stats["total_packets"] += 1
            if channel_type == "UART":
                self.stats["uart_count"] += 1
                self.stats["latest_uart_rtt"] = rtt_ms
            else:
                self.stats["mqtt_count"] += 1
                self.stats["latest_mqtt_rtt"] = rtt_ms

            self.stats["latest_throughput"] = tput

            if condition == "tampered":
                self.stats["tampered_packets"] += 1
                if not verified:
                    self.stats["rejected_packets"] += 1
            else:
                self.stats["normal_packets"] += 1
                if verified:
                    self.stats["accepted_packets"] += 1
                else:
                    self.stats["rejected_packets"] += 1

            t_tamp = self.stats["tampered_packets"]
            r_tamp = self.stats["rejected_packets"] - (self.stats["normal_packets"] - self.stats["accepted_packets"])
            self.stats["detection_rate_pct"] = round((r_tamp / t_tamp * 100.0) if t_tamp > 0 else 100.0, 1)

            t_norm = self.stats["normal_packets"]
            r_norm = t_norm - self.stats["accepted_packets"]
            self.stats["false_rejection_rate_pct"] = round((r_norm / t_norm * 100.0) if t_norm > 0 else 0.0, 1)

        # Pisahkan ciphertext dan 16-byte tag ASCON
        ct_bytes = used_ct[:-16] if len(used_ct) >= 16 else b""
        tag_bytes = used_ct[-16:] if len(used_ct) >= 16 else used_ct

        # Buat payload info event
        packet_event = {
            "type": "packet",
            "time": time.strftime("%H:%M:%S") + f".{int((time.time() % 1) * 1000):03d}",
            "device_id": device_id,
            "channel": channel_type,
            "condition": condition,
            "attack_variant": attack_variant,
            "payload_size": self.payload_size,
            "plaintext_preview": plaintext.decode("utf-8", errors="replace")[:55] + "...",
            "nonce_hex": used_nonce.hex()[:16] + "...",
            "tag_hex": tag_bytes.hex(),
            "ct_hex": ct_bytes.hex()[:20] + "...",
            "rtt_ms": rtt_ms,
            "throughput_bps": tput,
            "verified": verified,
            "decision": "ACCEPTED (VALID)" if verified else f"REJECTED: TAMPER DETECTED ({attack_variant or 'TAG MISMATCH'})",
            "cpu_percent": round(cpu_pct, 1),
            "ram_mb": round(ram_mb, 1),
            "stats": dict(self.stats),
        }

        self.recent_packets.append(packet_event)
        manager.broadcast_sync(packet_event)


worker = SimulationWorker()


# ---------------------------------------------------------------------------
# Rute & WebSockets
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Kirim status awal & history singkat
        init_payload = {
            "type": "init",
            "status": "running" if worker.running and not worker.paused else ("paused" if worker.paused else "stopped"),
            "stats": dict(worker.stats),
            "recent": list(worker.recent_packets),
        }
        await websocket.send_text(json.dumps(init_payload))
        while True:
            # Tetap jaga koneksi tetap hidup
            data = await websocket.receive_text()
            try:
                cmd = json.loads(data)
                if cmd.get("action") == "start":
                    worker.start(SimulationConfig(**cmd.get("config", {})))
                elif cmd.get("action") == "pause":
                    worker.pause()
                elif cmd.get("action") == "resume":
                    worker.resume()
                elif cmd.get("action") == "stop":
                    worker.stop()
                elif cmd.get("action") == "attack":
                    worker.queue_attack(cmd.get("variant", "bit_flip_ciphertext"))
                elif cmd.get("action") == "reset":
                    worker.reset_stats()
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/api/start")
def api_start(config: SimulationConfig):
    worker.start(config)
    return {"status": "started", "config": config.dict()}


@app.post("/api/pause")
def api_pause():
    worker.pause()
    return {"status": "paused"}


@app.post("/api/resume")
def api_resume():
    worker.resume()
    return {"status": "resumed"}


@app.post("/api/stop")
def api_stop():
    worker.stop()
    return {"status": "stopped"}


@app.post("/api/reset")
def api_reset():
    worker.reset_stats()
    return {"status": "reset", "stats": worker.stats}


@app.post("/api/inject_attack")
def api_inject_attack(req: AttackRequest):
    worker.queue_attack(req.variant)
    return {"status": "queued", "variant": req.variant}


@app.get("/api/status")
def api_status():
    return {
        "running": worker.running,
        "paused": worker.paused,
        "channel_mode": worker.channel_mode,
        "payload_size": worker.payload_size,
        "delay_ms": worker.delay_ms,
        "stats": worker.stats,
    }


# Sajikan berkas statis
if os.path.exists(RESULTS_DIR):
    app.mount("/results", StaticFiles(directory=RESULTS_DIR), name="results")

@app.get("/")
def get_index():
    index_path = os.path.join(DASHBOARD_DIR, "index.html")
    return FileResponse(index_path)

@app.get("/dashboard/index.html")
def get_dashboard_index():
    index_path = os.path.join(DASHBOARD_DIR, "index.html")
    return FileResponse(index_path)


if __name__ == "__main__":
    print("[SERVER] Menjalankan Live Real-Time Dashboard Server di http://localhost:8000 ...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

