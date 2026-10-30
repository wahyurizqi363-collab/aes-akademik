"""
Titik masuk aplikasi.

  GUI :  python main.py
  CLI :  python main.py encrypt  dokumen.pdf -k 256
         python main.py decrypt  dokumen.pdf.enc -k 256
         python main.py bench    file1.pdf file2.docx
"""
import argparse
import getpass
import sys

from app import crypto_engine as ce
from app import metrics


def cli(argv):
    p = argparse.ArgumentParser(description="Enkripsi data akademik AES + PBKDF2")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name)
        s.add_argument("file")
        s.add_argument("-o", "--output")
        s.add_argument("-k", "--key-bits", type=int, choices=ce.VALID_KEY_BITS, default=256)
    b = sub.add_parser("bench")
    b.add_argument("files", nargs="+")
    b.add_argument("--csv", default="hasil_benchmark.csv")
    a = p.parse_args(argv)

    try:
        if a.cmd in ("encrypt", "decrypt"):
            pw = getpass.getpass("Password: ")
            if a.cmd == "encrypt" and pw != getpass.getpass("Ulangi password: "):
                sys.exit("Password tidak cocok.")
            out = a.output or ce.default_output(a.file, a.cmd)
            fn = ce.encrypt_file if a.cmd == "encrypt" else ce.decrypt_file
            st = fn(a.file, out, pw, a.key_bits)
            print(f"Selesai -> {out}\nAES-{st['key_bits']} | {st['throughput']:.2f} MB/s | "
                  f"selisih ukuran {st['overhead']} B")
        else:
            pw = getpass.getpass("Password uji: ")
            rows = [metrics.benchmark_file(f, pw, k) for f in a.files for k in ce.VALID_KEY_BITS]
            for r in rows:
                print(f"{r['berkas']:<25} AES-{r['kunci_bit']:<3} {r['throughput_enkripsi_MBps']:>8} MB/s "
                      f"entropi {r['entropi_bit_per_byte']} avalanche {r['avalanche_persen']}% "
                      f"utuh={r['integritas_ok']}")
            metrics.export_csv(rows, a.csv)
            print(f"CSV: {a.csv}")
    except ce.CryptoError as e:
        sys.exit(f"Gagal: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        from app.gui import run
        run()
