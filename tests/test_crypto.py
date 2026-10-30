import os
import pytest

from app import crypto_engine as ce
from app import metrics

IT = 1000  # iterasi rendah agar tes cepat


@pytest.mark.parametrize("bits", ce.VALID_KEY_BITS)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1_048_576, 2_500_000])
def test_roundtrip_file(tmp_path, bits, size):
    src, enc, dec = (tmp_path / n for n in ("a.bin", "a.enc", "a.dec"))
    src.write_bytes(os.urandom(size))
    ce.encrypt_file(str(src), str(enc), "pw-rahasia", bits, iterations=IT)
    ce.decrypt_file(str(enc), str(dec), "pw-rahasia", bits, iterations=IT)
    assert src.read_bytes() == dec.read_bytes()


@pytest.mark.parametrize("size", [0, 1, 15, 16, 100, 4096, 123457])
def test_overhead_max_64(size):
    blob = ce.encrypt_bytes(os.urandom(size), "pw", 256, iterations=IT)
    assert 49 <= len(blob) - size <= 64


def test_wrong_password(tmp_path):
    src, enc, dec = (tmp_path / n for n in ("a.bin", "a.enc", "a.dec"))
    src.write_bytes(b"data akademik" * 1000)
    ce.encrypt_file(str(src), str(enc), "benar", 256, iterations=IT)
    with pytest.raises(ce.CryptoError):
        # padding acak bisa lolos dengan peluang kecil; ulangi dengan beberapa salah
        for p in ("salah1", "salah2", "salah3", "salah4"):
            ce.decrypt_file(str(enc), str(dec), p, 256, iterations=IT)
    assert not dec.exists()


def test_salt_iv_random():
    a = ce.encrypt_bytes(b"sama", "pw", 128, iterations=IT)
    b = ce.encrypt_bytes(b"sama", "pw", 128, iterations=IT)
    assert a != b


def test_invalid_file(tmp_path):
    bad = tmp_path / "bad.enc"
    bad.write_bytes(b"x" * 10)
    with pytest.raises(ce.CryptoError):
        ce.decrypt_file(str(bad), str(tmp_path / "o"), "pw", 256, iterations=IT)


def test_entropy_and_avalanche():
    data = os.urandom(50_000)
    blob = ce.encrypt_bytes(data, "pw", 256, iterations=IT)
    assert metrics.shannon_entropy(blob[ce.HEADER_SIZE:]) > 7.99
    assert 45 < metrics.avalanche_effect(data[:4096], "pw", 256, IT) < 55
