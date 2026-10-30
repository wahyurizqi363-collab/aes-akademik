"""Metrik evaluasi: entropi, avalanche effect, penggunaan CPU/RAM, benchmark."""
from __future__ import annotations

import csv
import hashlib
import math
import os
import tempfile
import threading
import time
from collections import Counter

import psutil

from . import crypto_engine as ce

SAMPLE_LIMIT = 8 * 1024 * 1024  # sampel maks. untuk entropi


def shannon_entropy(data: bytes) -> float:
    """Entropi Shannon dalam bit/byte (maksimum 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def bit_difference_percent(a: bytes, b: bytes) -> float:
    """Persentase bit yang berbeda antara dua byte-string (avalanche effect)."""
    length = min(len(a), len(b))
    if length == 0:
        return 0.0
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a[:length], b[:length]))
    return diff * 100.0 / (length * 8)


def avalanche_effect(sample: bytes, password: str, key_bits: int,
                     iterations: int = ce.KDF_ITERATIONS) -> float:
    """Ubah 1 bit plaintext lalu bandingkan ciphertext (salt & IV sama)."""
    if not sample:
        return 0.0
    salt, iv = os.urandom(ce.SALT_SIZE), os.urandom(ce.IV_SIZE)
    flipped = bytes([sample[0] ^ 0x01]) + sample[1:]
    c1 = ce.encrypt_bytes(sample, password, key_bits, salt, iv, iterations)[ce.HEADER_SIZE:]
    c2 = ce.encrypt_bytes(flipped, password, key_bits, salt, iv, iterations)[ce.HEADER_SIZE:]
    return bit_difference_percent(c1, c2)


class ResourceMonitor:
    """Sampling CPU (%) dan RAM (MB) proses aplikasi selama operasi berjalan."""

    def __init__(self, interval: float = 0.05):
        self.interval = interval
        self._proc = psutil.Process()
        self._cpus = psutil.cpu_count() or 1
        self._cpu, self._ram = [], []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            self._cpu.append(self._proc.cpu_percent(None) / self._cpus)
            self._ram.append(self._proc.memory_info().rss / (1024 * 1024))
            time.sleep(self.interval)

    def start(self):
        self._proc.cpu_percent(None)
        self._thread.start()

    def stop(self) -> tuple[float, float]:
        self._stop.set()
        self._thread.join()
        avg = lambda xs: sum(xs) / len(xs) if xs else 0.0
        return avg(self._cpu), avg(self._ram)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while c := f.read(1 << 20):
            h.update(c)
    return h.hexdigest()


def benchmark_file(path: str, password: str, key_bits: int,
                   iterations: int = ce.KDF_ITERATIONS) -> dict:
    """Jalankan enkripsi+dekripsi satu berkas dan kumpulkan seluruh metrik."""
    with tempfile.TemporaryDirectory() as tmp:
        enc_path = os.path.join(tmp, "x.enc")
        dec_path = os.path.join(tmp, "x.dec")

        mon = ResourceMonitor()
        mon.start()
        enc = ce.encrypt_file(path, enc_path, password, key_bits, iterations=iterations)
        dec = ce.decrypt_file(enc_path, dec_path, password, key_bits, iterations=iterations)
        cpu, ram = mon.stop()

        with open(enc_path, "rb") as f:
            entropy = shannon_entropy(f.read(SAMPLE_LIMIT)[ce.HEADER_SIZE:])
        with open(path, "rb") as f:
            sample = f.read(1024 * 1024)
        aval = avalanche_effect(sample, password, key_bits, iterations)

        return {
            "berkas": os.path.basename(path),
            "kunci_bit": key_bits,
            "ronde": ce.ROUNDS[key_bits],
            "ukuran_asli_byte": enc["plain_size"],
            "ukuran_enc_byte": enc["enc_size"],
            "overhead_byte": enc["overhead"],
            "waktu_kdf_s": round(enc["kdf_time"], 4),
            "waktu_enkripsi_s": round(enc["crypt_time"], 4),
            "waktu_dekripsi_s": round(dec["crypt_time"], 4),
            "throughput_enkripsi_MBps": round(enc["throughput"], 2),
            "throughput_dekripsi_MBps": round(dec["throughput"], 2),
            "entropi_bit_per_byte": round(entropy, 4),
            "avalanche_persen": round(aval, 2),
            "cpu_persen": round(cpu, 2),
            "ram_MB": round(ram, 1),
            "integritas_ok": _sha256(path) == _sha256(dec_path),
        }


def export_csv(rows: list[dict], path: str) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
