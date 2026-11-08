"""
receiver_server.py
====================
Penerima UART & MQTT: menerima paket dari jalur UART maupun MQTT, melakukan
verifikasi tag ASCON, dekripsi ASCON-128, penyimpanan hasil valid ke SQLite,
serta pencatatan log.
"""

import sqlite3
import threading
import time
import os

import crypto_utils
from metrics import ResourceMonitor

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "log.sqlite")

# Lock GLOBAL (bukan per-instance): pada simulasi ini setiap transaksi paket
# membuat instance ReceiverServer baru namun seluruhnya berbagi satu koneksi
# SQLite (db_conn), sehingga penguncian akses tulis harus dibagi lintas
# instance, bukan melekat pada satu instance saja.
_DB_WRITE_LOCK = threading.Lock()


def init_db(db_path: str = DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    # check_same_thread=False: koneksi diakses dari banyak thread penerima
    # (satu thread per transaksi paket); akses ditulis-aman lewat self._lock
    # pada ReceiverServer._handle_packet.
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS valid_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            channel TEXT,
            payload TEXT,
            received_at REAL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            channel TEXT,
            condition_label TEXT,
            attack_variant TEXT,
            result TEXT,
            received_at REAL
        )
    """)
    conn.commit()
    return conn


class ReceiverServer:
    """Menjalankan satu loop penerima untuk satu jalur komunikasi (UART atau
    MQTT). Setiap paket yang masuk diverifikasi (tag ASCON) & didekripsi;
    hasil valid disimpan ke SQLite, seluruh hasil (valid/ditolak) dicatat
    pada tabel log. Sisi penerima juga membalas dengan ACK/NACK agar
    pengirim dapat mengukur RTT round-trip penuh."""

    NONCE_LEN = 16
    HEADER_LEN = 16

    def __init__(self, key: bytes, channel_type: str, db_conn: sqlite3.Connection,
                 resource_monitor: ResourceMonitor = None):
        self.key = key
        self.channel_type = channel_type
        self.db_conn = db_conn
        self.resource_monitor = resource_monitor
        self._lock = _DB_WRITE_LOCK
        self._running = False
        self._thread = None

    def _handle_packet(self, packet: bytes, channel):
        header = packet[:self.HEADER_LEN]
        nonce = packet[self.HEADER_LEN:self.HEADER_LEN + self.NONCE_LEN]
        ct_and_tag = packet[self.HEADER_LEN + self.NONCE_LEN:]
        device_id = header.rstrip(b"\x00").decode("utf-8", errors="replace")
        associated_data = header.rstrip(b"\x00")

        plaintext = crypto_utils.decrypt(self.key, nonce, ct_and_tag, associated_data)

        with self._lock:
            cur = self.db_conn.cursor()
            if plaintext is not None:
                cur.execute(
                    "INSERT INTO valid_data (device_id, channel, payload, received_at) "
                    "VALUES (?, ?, ?, ?)",
                    (device_id, self.channel_type, plaintext.decode("utf-8", errors="replace"),
                     time.time()),
                )
                cur.execute(
                    "INSERT INTO verification_log "
                    "(device_id, channel, condition_label, attack_variant, result, received_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (device_id, self.channel_type, "unknown", "", "ACCEPTED", time.time()),
                )
            else:
                cur.execute(
                    "INSERT INTO verification_log "
                    "(device_id, channel, condition_label, attack_variant, result, received_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (device_id, self.channel_type, "unknown", "", "REJECTED", time.time()),
                )
            self.db_conn.commit()

        reply = b"ACK" if plaintext is not None else b"NACK"
        channel.reply(reply)
        return plaintext is not None

    def serve_uart_once(self, channel, timeout: float = 5.0):
        packet = channel.receive(timeout=timeout)
        if packet is None:
            return None
        return self._handle_packet(packet, channel)

    def serve_mqtt_forever(self, channel, uplink_queue, stop_event: threading.Event):
        """Loop subscriber MQTT: menunggu pesan pada topic uplink perangkat
        tertentu hingga stop_event di-set."""
        while not stop_event.is_set():
            try:
                packet = uplink_queue.get(timeout=0.5)
            except Exception:
                continue
            self._handle_packet(packet, channel)


def get_summary_counts(db_conn: sqlite3.Connection):
    cur = db_conn.cursor()
    cur.execute("SELECT result, COUNT(*) FROM verification_log GROUP BY result")
    return dict(cur.fetchall())
