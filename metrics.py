"""
metrics.py
===========
Merekam latensi (Round-Trip Time), throughput, serta penggunaan CPU dan RAM
pada sisi pengirim dan penerima.
"""

import time
import threading
import psutil
from dataclasses import dataclass, field
from typing import List


class Stopwatch:
    """Context manager sederhana untuk mengukur durasi (detik)."""

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed_s = time.perf_counter() - self._t0
        return False


@dataclass
class ResourceSample:
    timestamp: float
    cpu_percent: float
    ram_mb: float


class ResourceMonitor:
    """Mencuplik penggunaan CPU & RAM proses saat ini pada interval tetap
    (default 1 detik) di thread terpisah, agar tidak mengganggu pengukuran
    latensi jalur komunikasi."""

    def __init__(self, interval_s: float = 1.0):
        self.interval_s = interval_s
        self._process = psutil.Process()
        self._samples: List[ResourceSample] = []
        self._stop_event = threading.Event()
        self._thread = None
        # panggilan pertama cpu_percent() selalu 0.0 -> "warm-up"
        self._process.cpu_percent(interval=None)

    def _run(self):
        while not self._stop_event.is_set():
            cpu = self._process.cpu_percent(interval=None)
            ram_mb = self._process.memory_info().rss / (1024 * 1024)
            self._samples.append(ResourceSample(time.time(), cpu, ram_mb))
            self._stop_event.wait(self.interval_s)

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2 * self.interval_s)

    def snapshot(self):
        """Mengambil satu cuplikan instan CPU% & RAM (MB) tanpa menunggu."""
        cpu = self._process.cpu_percent(interval=None)
        ram_mb = self._process.memory_info().rss / (1024 * 1024)
        return cpu, ram_mb

    @property
    def samples(self) -> List[ResourceSample]:
        return list(self._samples)

    def mean_cpu(self) -> float:
        if not self._samples:
            return 0.0
        return sum(s.cpu_percent for s in self._samples) / len(self._samples)

    def mean_ram_mb(self) -> float:
        if not self._samples:
            return 0.0
        return sum(s.ram_mb for s in self._samples) / len(self._samples)


def throughput_bps(n_bytes: int, elapsed_s: float) -> float:
    """Throughput dalam byte per detik (menghindari pembagian dengan nol)."""
    if elapsed_s <= 0:
        return 0.0
    return n_bytes / elapsed_s


@dataclass
class PacketRecord:
    """Satu baris hasil pengukuran untuk satu paket yang dikirim."""
    scenario: str
    channel: str
    condition: str            # "normal" atau "tampered"
    attack_variant: str        # "" jika normal
    payload_size: int
    n_devices: int
    repetition: int
    rtt_ms: float
    throughput_bps: float
    cpu_percent_sender: float
    ram_mb_sender: float
    cpu_percent_receiver: float
    ram_mb_receiver: float
    verified: bool             # True jika tag valid & diterima
    timestamp: float = field(default_factory=time.time)
