"""
mqtt_channel.py
================
Modul komunikasi publish/subscribe menuju broker MQTT (Mosquitto).

Lingkungan eksekusi tidak memiliki akses jaringan untuk memasang `paho-mqtt`
maupun menjalankan broker Mosquitto sungguhan, sehingga broker & jalur
publish/subscribe direpresentasikan sebagai in-memory broker yang meniru
perilaku MQTT QoS 1 (publish -> broker -> deliver ke subscriber, dengan
overhead protokol tambahan dibanding UART: proses hashing topic, antrean
broker, dan RTT yang umumnya lebih tinggi & lebih bervariasi karena
melalui jaringan/broker perantara).

Jika dijalankan dengan broker Mosquitto sungguhan, kelas ini dapat diganti
dengan implementasi berbasis `paho-mqtt` (mqtt.Client) tanpa mengubah
antarmuka (publish/receive) yang dipakai oleh device_sim.py & receiver_server.py.
"""

import random
import time
import queue
import threading


class _InMemoryBroker:
    """Broker MQTT tiruan: mendistribusikan pesan dari topic tertentu ke
    seluruh subscriber topic tersebut, dengan overhead pemrosesan broker."""

    def __init__(self, broker_latency_ms: float = 4.0, jitter_ms: float = 3.0):
        self.broker_latency_ms = broker_latency_ms
        self.jitter_ms = jitter_ms
        self._subscribers = {}
        self._lock = threading.Lock()

    def subscribe(self, topic: str) -> "queue.Queue[bytes]":
        with self._lock:
            q: "queue.Queue[bytes]" = queue.Queue()
            self._subscribers.setdefault(topic, []).append(q)
            return q

    def publish(self, topic: str, payload: bytes):
        delay_s = (self.broker_latency_ms + random.uniform(0, self.jitter_ms)) / 1000.0
        time.sleep(delay_s)
        with self._lock:
            for q in self._subscribers.get(topic, []):
                q.put(payload)
        return delay_s


class MQTTChannel:
    """Merepresentasikan jalur publish/subscribe MQTT untuk satu perangkat.
    Topic uplink dipakai perangkat->penerima, topic downlink untuk balasan
    (ack/nack) penerima->perangkat, meniru pola request/response berbasis
    dua topic (umum dipakai pada aplikasi telemetri IoT)."""

    _shared_broker = _InMemoryBroker()

    def __init__(self, device_id: str, network_latency_ms: float = 8.0,
                 jitter_ms: float = 5.0, broker: "_InMemoryBroker" = None):
        self.device_id = device_id
        self.network_latency_ms = network_latency_ms
        self.jitter_ms = jitter_ms
        self.broker = broker or MQTTChannel._shared_broker
        self.uplink_topic = f"iot/sensor/{device_id}/data"
        self.downlink_topic = f"iot/sensor/{device_id}/ack"
        self._downlink_queue = self.broker.subscribe(self.downlink_topic)

    def _network_delay_s(self) -> float:
        return (self.network_latency_ms + random.uniform(0, self.jitter_ms)) / 1000.0

    def subscribe_uplink(self):
        """Dipanggil sisi penerima (subscriber) untuk mendengarkan topik data."""
        return self.broker.subscribe(self.uplink_topic)

    def publish(self, payload: bytes) -> float:
        """Device mem-publish payload terenkripsi ke topic data (uplink)."""
        net_delay = self._network_delay_s()
        time.sleep(net_delay)
        broker_delay = self.broker.publish(self.uplink_topic, payload)
        return net_delay + broker_delay

    def reply(self, payload: bytes) -> float:
        """Penerima mem-publish balasan (ack/nack) ke topic downlink."""
        net_delay = self._network_delay_s()
        time.sleep(net_delay)
        broker_delay = self.broker.publish(self.downlink_topic, payload)
        return net_delay + broker_delay

    def wait_reply(self, timeout: float = 5.0):
        """Device menunggu balasan ack/nack dari penerima untuk mengukur RTT."""
        try:
            return self._downlink_queue.get(timeout=timeout)
        except queue.Empty:
            return None
