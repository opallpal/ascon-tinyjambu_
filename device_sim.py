"""
device_sim.py
==============
Simulator perangkat IoT: membangkitkan data sensor sintetis (suhu,
kelembaban, cahaya) dalam format JSON dengan ukuran payload bertingkat,
mengenkripsinya dengan ASCON-128 AEAD, lalu mengirimkannya melalui UART
atau MQTT ke penerima.
"""

import json
import random
import string
import time

import crypto_utils
import attacker
from metrics import Stopwatch, throughput_bps, PacketRecord


def generate_sensor_reading(target_size_bytes: int = 64) -> bytes:
    """Membangkitkan satu pembacaan sensor sintetis (suhu/kelembaban/cahaya)
    dalam format JSON, lalu diisi field 'padding' agar total ukuran payload
    JSON mendekati target_size_bytes (mensimulasikan payload bertingkat)."""
    reading = {
        "ts": round(time.time(), 3),
        "temp_c": round(random.uniform(20.0, 35.0), 2),
        "hum_pct": round(random.uniform(30.0, 90.0), 2),
        "lux": round(random.uniform(0.0, 1000.0), 1),
    }
    base = json.dumps(reading, separators=(",", ":"))
    pad_needed = max(0, target_size_bytes - len(base) - len('"pad":""'))
    reading["pad"] = "".join(random.choices(string.ascii_lowercase, k=pad_needed))
    payload = json.dumps(reading, separators=(",", ":")).encode("utf-8")
    return payload


class IoTDevice:
    """Merepresentasikan satu node pengirim (mikrokontroler ESP32 atau
    perangkat sejenis) yang membangkitkan, mengenkripsi, dan mengirim data
    sensor melalui satu jalur komunikasi (UART atau MQTT)."""

    def __init__(self, device_id: str, key: bytes, channel, channel_type: str,
                 resource_monitor=None):
        self.device_id = device_id
        self.key = key
        self.channel = channel        # instance UARTChannel atau MQTTChannel
        self.channel_type = channel_type  # "UART" atau "MQTT"
        self.resource_monitor = resource_monitor

    def _send_raw(self, payload: bytes) -> float:
        if self.channel_type == "UART":
            return self.channel.send(payload)
        elif self.channel_type == "MQTT":
            return self.channel.publish(payload)
        raise ValueError(f"channel_type tidak dikenal: {self.channel_type}")

    def _wait_ack(self, timeout: float = 5.0):
        return self.channel.wait_reply(timeout=timeout)

    def send_packet(self, scenario: str, payload_size: int, n_devices: int,
                     repetition: int, condition: str = "normal",
                     attack_variant: str = None) -> PacketRecord:
        """Membangkitkan satu paket sensor, mengenkripsi (dan bila
        condition='tampered', memanipulasinya), mengirim, lalu menunggu
        ack/nack dari penerima untuk mengukur RTT."""
        associated_data = self.device_id.encode("utf-8")
        plaintext = generate_sensor_reading(payload_size)
        nonce = crypto_utils.generate_nonce()
        ct_and_tag = crypto_utils.encrypt(self.key, nonce, plaintext, associated_data)

        used_key, used_nonce, used_ct = self.key, nonce, ct_and_tag
        if condition == "tampered":
            tampered = attacker.generate_tampered_packet(
                self.key, nonce, ct_and_tag, variant=attack_variant,
                plaintext=plaintext, associated_data=associated_data)
            used_key, used_nonce, used_ct = tampered.key, tampered.nonce, tampered.ciphertext_and_tag
            attack_variant = tampered.variant

        # bungkus paket: device_id (utk AD) || nonce || ciphertext_and_tag
        header = self.device_id.encode("utf-8").ljust(16, b"\x00")[:16]
        packet = header + used_nonce + used_ct

        cpu_before, ram_before = (0.0, 0.0)
        if self.resource_monitor:
            cpu_before, ram_before = self.resource_monitor.snapshot()

        with Stopwatch() as sw:
            self._send_raw(packet)
            reply = self._wait_ack(timeout=5.0)
        rtt_ms = sw.elapsed_s * 1000.0

        verified = bool(reply == b"ACK")
        tput = throughput_bps(len(packet), sw.elapsed_s)

        cpu_after, ram_after = (0.0, 0.0)
        if self.resource_monitor:
            cpu_after, ram_after = self.resource_monitor.snapshot()

        return PacketRecord(
            scenario=scenario,
            channel=self.channel_type,
            condition=condition,
            attack_variant=attack_variant or "",
            payload_size=payload_size,
            n_devices=n_devices,
            repetition=repetition,
            rtt_ms=rtt_ms,
            throughput_bps=tput,
            cpu_percent_sender=(cpu_before + cpu_after) / 2,
            ram_mb_sender=(ram_before + ram_after) / 2,
            cpu_percent_receiver=0.0,   # diisi oleh sisi penerima secara terpisah
            ram_mb_receiver=0.0,
            verified=verified,
        )
