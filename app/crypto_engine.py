"""
Mesin kriptografi: AES-CBC (128/192/256-bit) dengan manajemen kunci
berbasis password menggunakan PBKDF2-HMAC-SHA256.

Format berkas terenkripsi (.enc):
    [ SALT 32 byte ][ IV 16 byte ][ CIPHERTEXT (kelipatan 16 byte, PKCS7) ]

Overhead ukuran = 32 (salt) + 16 (IV) + padding 1..16 byte  => 49..64 byte,
sehingga overhead maksimum konstan 64 byte berapapun ukuran berkas asli.
"""
from __future__ import annotations

import os
import tempfile
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 32
IV_SIZE = 16
BLOCK = 16
HEADER_SIZE = SALT_SIZE + IV_SIZE          # 48 byte
KDF_ITERATIONS = 600_000                   # rekomendasi OWASP untuk PBKDF2-SHA256
CHUNK_SIZE = 1024 * 1024                   # 1 MiB
VALID_KEY_BITS = (128, 192, 256)
ROUNDS = {128: 10, 192: 12, 256: 14}       # jumlah ronde internal AES
EXT = ".enc"

ProgressCB = Optional[Callable[[int, int], None]]


class CryptoError(Exception):
    """Kesalahan umum proses kriptografi."""


class WrongPasswordError(CryptoError):
    """Password salah atau berkas rusak."""


def _check_key_bits(key_bits: int) -> None:
    if key_bits not in VALID_KEY_BITS:
        raise CryptoError(f"Panjang kunci harus salah satu dari {VALID_KEY_BITS}")


def derive_key(password: str, salt: bytes, key_bits: int,
               iterations: int = KDF_ITERATIONS) -> bytes:
    """Turunkan kunci AES dari password memakai PBKDF2-HMAC-SHA256."""
    _check_key_bits(key_bits)
    if not password:
        raise CryptoError("Password tidak boleh kosong.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_bits // 8,
                     salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


# --------------------------------------------------------------------------
# Operasi pada bytes (dipakai untuk pengujian & avalanche effect)
# --------------------------------------------------------------------------
def encrypt_bytes(data: bytes, password: str, key_bits: int = 256,
                  salt: bytes | None = None, iv: bytes | None = None,
                  iterations: int = KDF_ITERATIONS) -> bytes:
    salt = salt or os.urandom(SALT_SIZE)
    iv = iv or os.urandom(IV_SIZE)
    key = derive_key(password, salt, key_bits, iterations)
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
    return salt + iv + ct


def decrypt_bytes(blob: bytes, password: str, key_bits: int = 256,
                  iterations: int = KDF_ITERATIONS) -> bytes:
    if len(blob) < HEADER_SIZE + BLOCK or (len(blob) - HEADER_SIZE) % BLOCK:
        raise CryptoError("Format berkas tidak valid.")
    salt, iv, ct = blob[:SALT_SIZE], blob[SALT_SIZE:HEADER_SIZE], blob[HEADER_SIZE:]
    key = derive_key(password, salt, key_bits, iterations)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(dec.update(ct) + dec.finalize()) + unpadder.finalize()
    except ValueError as exc:
        raise WrongPasswordError("Password salah atau berkas rusak.") from exc


# --------------------------------------------------------------------------
# Operasi pada berkas (streaming, aman untuk berkas besar)
# --------------------------------------------------------------------------
def encrypt_file(src: str, dst: str, password: str, key_bits: int = 256,
                 progress: ProgressCB = None,
                 iterations: int = KDF_ITERATIONS) -> dict:
    """Enkripsi berkas. Mengembalikan statistik kinerja."""
    _check_key_bits(key_bits)
    if os.path.abspath(src) == os.path.abspath(dst):
        raise CryptoError("Berkas sumber dan tujuan tidak boleh sama.")
    total = os.path.getsize(src)

    t0 = time.perf_counter()
    salt, iv = os.urandom(SALT_SIZE), os.urandom(IV_SIZE)
    key = derive_key(password, salt, key_bits, iterations)
    t_kdf = time.perf_counter() - t0

    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(dst)), suffix=".tmp")
    done = 0
    t1 = time.perf_counter()
    try:
        with os.fdopen(fd, "wb") as fout, open(src, "rb") as fin:
            fout.write(salt + iv)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(enc.update(padder.update(chunk)))
                done += len(chunk)
                if progress:
                    progress(done, total)
            fout.write(enc.update(padder.finalize()) + enc.finalize())
        t_crypt = time.perf_counter() - t1
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return _stats(total, os.path.getsize(dst), t_kdf, t_crypt, key_bits)


def decrypt_file(src: str, dst: str, password: str, key_bits: int = 256,
                 progress: ProgressCB = None,
                 iterations: int = KDF_ITERATIONS) -> dict:
    """Dekripsi berkas. Memunculkan WrongPasswordError bila password salah."""
    _check_key_bits(key_bits)
    if os.path.abspath(src) == os.path.abspath(dst):
        raise CryptoError("Berkas sumber dan tujuan tidak boleh sama.")
    size = os.path.getsize(src)
    if size < HEADER_SIZE + BLOCK or (size - HEADER_SIZE) % BLOCK:
        raise CryptoError("Format berkas tidak valid / bukan berkas hasil aplikasi ini.")

    t0 = time.perf_counter()
    with open(src, "rb") as fin:
        header = fin.read(HEADER_SIZE)
    salt, iv = header[:SALT_SIZE], header[SALT_SIZE:]
    key = derive_key(password, salt, key_bits, iterations)
    t_kdf = time.perf_counter() - t0

    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(dst)), suffix=".tmp")
    done, total = 0, size - HEADER_SIZE
    t1 = time.perf_counter()
    try:
        with os.fdopen(fd, "wb") as fout, open(src, "rb") as fin:
            fin.seek(HEADER_SIZE)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(unpadder.update(dec.update(chunk)))
                done += len(chunk)
                if progress:
                    progress(done, total)
            fout.write(unpadder.update(dec.finalize()) + unpadder.finalize())
        t_crypt = time.perf_counter() - t1
        os.replace(tmp, dst)
    except ValueError as exc:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise WrongPasswordError("Password salah atau berkas rusak.") from exc
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return _stats(os.path.getsize(dst), size, t_kdf, t_crypt, key_bits)


def _stats(plain: int, enc: int, t_kdf: float, t_crypt: float, key_bits: int) -> dict:
    mb = max(plain, 1) / (1024 * 1024)
    return {
        "key_bits": key_bits,
        "rounds": ROUNDS[key_bits],
        "plain_size": plain,
        "enc_size": enc,
        "overhead": abs(enc - plain),
        "kdf_time": t_kdf,
        "crypt_time": t_crypt,
        "throughput": mb / t_crypt if t_crypt > 0 else float("inf"),
    }


def default_output(path: str, mode: str) -> str:
    """Nama berkas keluaran bawaan."""
    if mode == "encrypt":
        return path + EXT
    if path.lower().endswith(EXT):
        return path[: -len(EXT)]
    return path + ".dec"
