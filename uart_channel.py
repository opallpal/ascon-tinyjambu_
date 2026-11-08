"""
uart_channel.py
================
Modul komunikasi UART antara simulator perangkat dan penerima.

Karena lingkungan eksekusi tidak memiliki port serial fisik/virtual maupun
akses untuk memasang `pyserial`, jalur UART direpresentasikan sebagai
in-memory channel yang memodelkan karakteristik UART nyata:
  - latensi rendah & stabil (mendekati komunikasi serial jarak dekat)
  - jitter kecil
  - throughput dibatasi oleh baudrate yang dikonfigurasi
  - transmisi bersifat point-to-point (satu pengirim -> satu penerima)

Jika dijalankan pada perangkat keras sungguhan, kelas ini cukup diganti
dengan implementasi berbasis `pyserial` (serial.Serial) tanpa mengubah
antarmuka (send/receive) yang dipakai oleh device_sim.py & receiver_server.py.
"""

import random
import time
import queue


class UARTChannel:
    """Merepresentasikan satu jalur UART point-to-point full-duplex yang
    disimulasikan di dalam memori (dua antrean: uplink & downlink)."""

    def __init__(self, baudrate: int = 115200, base_latency_ms: float = 2.0,
                 jitter_ms: float = 0.5):
        self.baudrate = baudrate
        self.base_latency_ms = base_latency_ms
        self.jitter_ms = jitter_ms
        self._uplink: "queue.Queue[bytes]" = queue.Queue()
        self._downlink: "queue.Queue[bytes]" = queue.Queue()

    def _transmission_delay_s(self, n_bytes: int) -> float:
        """Menghitung waktu transmisi berdasarkan baudrate (10 bit/byte utk
        format 8N1) ditambah latensi dasar & jitter acak."""
        bits = n_bytes * 10
        tx_time_s = bits / self.baudrate
        latency_s = (self.base_latency_ms + random.uniform(0, self.jitter_ms)) / 1000.0
        return tx_time_s + latency_s

    def send(self, payload: bytes) -> float:
        """Node pengirim (device) mengirim payload ke penerima.
        Mengembalikan delay simulasi (detik) yang telah diterapkan."""
        delay = self._transmission_delay_s(len(payload))
        time.sleep(delay)
        self._uplink.put(payload)
        return delay

    def receive(self, timeout: float = 5.0):
        """Sisi penerima menunggu & mengambil payload dari uplink."""
        try:
            return self._uplink.get(timeout=timeout)
        except queue.Empty:
            return None

    def reply(self, payload: bytes) -> float:
        """Penerima mengirim balasan (ack/nack) ke pengirim melalui downlink."""
        delay = self._transmission_delay_s(len(payload))
        time.sleep(delay)
        self._downlink.put(payload)
        return delay

    def wait_reply(self, timeout: float = 5.0):
        """Pengirim menunggu balasan dari penerima untuk mengukur RTT."""
        try:
            return self._downlink.get(timeout=timeout)
        except queue.Empty:
            return None
