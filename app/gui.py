"""Antarmuka desktop (Tkinter) untuk Aplikasi Enkripsi Data Akademik."""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from . import crypto_engine as ce
from . import metrics


def password_strength(pw: str) -> tuple[str, str]:
    score = sum([len(pw) >= 8, len(pw) >= 12,
                 any(c.islower() for c in pw) and any(c.isupper() for c in pw),
                 any(c.isdigit() for c in pw),
                 any(not c.isalnum() for c in pw)])
    if not pw:
        return "", "gray"
    if score <= 2:
        return "Lemah", "#c0392b"
    if score <= 3:
        return "Sedang", "#d68910"
    return "Kuat", "#1e8449"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Enkripsi Data Akademik - AES + PBKDF2  v{__version__}")
        self.geometry("920x640")
        self.minsize(820, 580)
        self.q: queue.Queue = queue.Queue()
        self.busy = False

        self.bench_files: list[str] = []
        self.bench_rows: list[dict] = []

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_main = ttk.Frame(nb, padding=14)
        self.tab_bench = ttk.Frame(nb, padding=14)
        nb.add(self.tab_main, text="Enkripsi / Dekripsi")
        nb.add(self.tab_bench, text="Evaluasi Kinerja")
        self._build_main()
        self._build_bench()

        self.status = tk.StringVar(value="Siap.")
        ttk.Label(self, textvariable=self.status, relief="sunken",
                  anchor="w", padding=4).pack(fill="x", side="bottom")
        self.after(100, self._poll)

    # ------------------------------------------------------------------ UI
    def _build_main(self):
        f = self.tab_main
        f.columnconfigure(1, weight=1)
        self.mode = tk.StringVar(value="encrypt")
        self.src = tk.StringVar()
        self.dst = tk.StringVar()
        self.pw = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.bits = tk.IntVar(value=256)
        self.show = tk.BooleanVar(value=False)

        box = ttk.Frame(f)
        box.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Radiobutton(box, text="Enkripsi", variable=self.mode, value="encrypt",
                        command=self._mode_changed).pack(side="left", padx=(0, 16))
        ttk.Radiobutton(box, text="Dekripsi", variable=self.mode, value="decrypt",
                        command=self._mode_changed).pack(side="left")

        ttk.Label(f, text="Berkas sumber").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.src).grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Button(f, text="Pilih...", command=self._pick_src).grid(row=1, column=2)

        ttk.Label(f, text="Berkas keluaran").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.dst).grid(row=2, column=1, sticky="ew", padx=6)
        ttk.Button(f, text="Simpan ke...", command=self._pick_dst).grid(row=2, column=2)

        ttk.Label(f, text="Panjang kunci AES").grid(row=3, column=0, sticky="w", pady=4)
        kb = ttk.Frame(f)
        kb.grid(row=3, column=1, sticky="w", padx=6)
        for b in ce.VALID_KEY_BITS:
            ttk.Radiobutton(kb, text=f"AES-{b} ({ce.ROUNDS[b]} ronde)", variable=self.bits,
                            value=b).pack(side="left", padx=(0, 14))

        ttk.Label(f, text="Password").grid(row=4, column=0, sticky="w", pady=4)
        self.e_pw = ttk.Entry(f, textvariable=self.pw, show="•")
        self.e_pw.grid(row=4, column=1, sticky="ew", padx=6)
        self.lbl_strength = ttk.Label(f, text="")
        self.lbl_strength.grid(row=4, column=2)
        self.pw.trace_add("write", self._strength)

        self.lbl_pw2 = ttk.Label(f, text="Ulangi password")
        self.lbl_pw2.grid(row=5, column=0, sticky="w", pady=4)
        self.e_pw2 = ttk.Entry(f, textvariable=self.pw2, show="•")
        self.e_pw2.grid(row=5, column=1, sticky="ew", padx=6)

        ttk.Checkbutton(f, text="Tampilkan password", variable=self.show,
                        command=self._toggle_show).grid(row=6, column=1, sticky="w", padx=6)

        self.btn_run = ttk.Button(f, text="Jalankan", command=self._run)
        self.btn_run.grid(row=7, column=1, sticky="w", padx=6, pady=14)

        self.prog = ttk.Progressbar(f, mode="determinate", maximum=100)
        self.prog.grid(row=8, column=0, columnspan=3, sticky="ew")

        self.log = tk.Text(f, height=12, state="disabled", wrap="word")
        self.log.grid(row=9, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
        f.rowconfigure(9, weight=1)

        note = ("Catatan: password tidak disimpan. Jika password hilang, data tidak dapat "
                "dipulihkan. Untuk dekripsi, pilih panjang kunci yang sama dengan saat enkripsi.")
        ttk.Label(f, text=note, wraplength=820, foreground="gray").grid(
            row=10, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_bench(self):
        f = self.tab_bench
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Button(top, text="Tambah berkas uji...", command=self._bench_add).pack(side="left")
        ttk.Button(top, text="Kosongkan", command=self._bench_clear).pack(side="left", padx=6)
        ttk.Label(top, text="Password uji:").pack(side="left", padx=(16, 4))
        self.bench_pw = tk.StringVar(value="PasswordUji#2026")
        ttk.Entry(top, textvariable=self.bench_pw, width=22).pack(side="left")
        self.btn_bench = ttk.Button(top, text="Mulai evaluasi", command=self._bench_run)
        self.btn_bench.pack(side="left", padx=12)
        ttk.Button(top, text="Ekspor CSV", command=self._bench_export).pack(side="left")

        self.lbl_files = ttk.Label(f, text="Belum ada berkas dipilih.")
        self.lbl_files.grid(row=1, column=0, sticky="w", pady=6)
        self.bprog = ttk.Progressbar(f, mode="determinate", maximum=1)
        self.bprog.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        cols = ("berkas", "kunci", "ronde", "overhead", "enc_MBps", "dec_MBps",
                "entropi", "avalanche", "cpu", "ram", "ok")
        heads = ("Berkas", "Kunci", "Ronde", "Overhead (B)", "Enkripsi MB/s", "Dekripsi MB/s",
                 "Entropi", "Avalanche %", "CPU %", "RAM MB", "Utuh")
        self.tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, h in zip(cols, heads):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=70 if c != "berkas" else 170, anchor="center")
        self.tree.grid(row=3, column=0, sticky="nsew")
        sb = ttk.Scrollbar(f, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.grid(row=3, column=1, sticky="ns")

        self.lbl_summary = ttk.Label(f, text="", justify="left")
        self.lbl_summary.grid(row=4, column=0, sticky="w", pady=(8, 0))

    # -------------------------------------------------------------- helpers
    def _mode_changed(self):
        enc = self.mode.get() == "encrypt"
        for w in (self.lbl_pw2, self.e_pw2):
            (w.grid if enc else w.grid_remove)()
        if self.src.get():
            self.dst.set(ce.default_output(self.src.get(), self.mode.get()))

    def _toggle_show(self):
        ch = "" if self.show.get() else "•"
        self.e_pw.config(show=ch)
        self.e_pw2.config(show=ch)

    def _strength(self, *_):
        t, c = password_strength(self.pw.get())
        self.lbl_strength.config(text=t, foreground=c)

    def _pick_src(self):
        p = filedialog.askopenfilename(title="Pilih berkas")
        if p:
            self.src.set(p)
            self.dst.set(ce.default_output(p, self.mode.get()))

    def _pick_dst(self):
        p = filedialog.asksaveasfilename(title="Simpan keluaran", initialfile=os.path.basename(self.dst.get()))
        if p:
            self.dst.set(p)

    def _log(self, text: str):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    # ------------------------------------------------------- enkripsi/dekripsi
    def _run(self):
        if self.busy:
            return
        src, dst, pw = self.src.get().strip(), self.dst.get().strip(), self.pw.get()
        mode, bits = self.mode.get(), self.bits.get()
        if not src or not os.path.isfile(src):
            return messagebox.showwarning("Peringatan", "Pilih berkas sumber yang valid.")
        if not dst:
            return messagebox.showwarning("Peringatan", "Tentukan berkas keluaran.")
        if not pw:
            return messagebox.showwarning("Peringatan", "Password tidak boleh kosong.")
        if mode == "encrypt":
            if pw != self.pw2.get():
                return messagebox.showwarning("Peringatan", "Konfirmasi password tidak cocok.")
            if len(pw) < 8 and not messagebox.askyesno(
                    "Password pendek", "Password kurang dari 8 karakter. Tetap lanjutkan?"):
                return
        if os.path.exists(dst) and not messagebox.askyesno(
                "Timpa berkas?", f"{os.path.basename(dst)} sudah ada. Timpa?"):
            return

        self.busy = True
        self.btn_run.config(state="disabled")
        self.prog["value"] = 0
        self.status.set("Memproses...")
        fn = ce.encrypt_file if mode == "encrypt" else ce.decrypt_file

        def work():
            try:
                st = fn(src, dst, pw, bits,
                        progress=lambda d, t: self.q.put(("p", d * 100 / max(t, 1))))
                self.q.put(("done", mode, dst, st))
            except ce.CryptoError as e:
                self.q.put(("err", str(e)))
            except Exception as e:  # noqa: BLE001
                self.q.put(("err", f"Terjadi kesalahan: {e}"))

        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------- benchmark
    def _bench_add(self):
        ps = filedialog.askopenfilenames(title="Pilih berkas uji")
        self.bench_files.extend(p for p in ps if p not in self.bench_files)
        self.lbl_files.config(text=f"{len(self.bench_files)} berkas dipilih.")

    def _bench_clear(self):
        self.bench_files.clear()
        self.bench_rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.lbl_files.config(text="Belum ada berkas dipilih.")
        self.lbl_summary.config(text="")

    def _bench_run(self):
        if self.busy:
            return
        if not self.bench_files:
            return messagebox.showwarning("Peringatan", "Tambahkan berkas uji terlebih dahulu.")
        pw = self.bench_pw.get()
        if not pw:
            return messagebox.showwarning("Peringatan", "Password uji tidak boleh kosong.")
        self.busy = True
        self.btn_bench.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.bench_rows.clear()
        jobs = [(f, b) for f in self.bench_files for b in ce.VALID_KEY_BITS]
        self.bprog.config(maximum=len(jobs), value=0)
        self.status.set("Evaluasi berjalan...")

        def work():
            try:
                for i, (f, b) in enumerate(jobs, 1):
                    row = metrics.benchmark_file(f, pw, b)
                    self.q.put(("brow", row, i))
                self.q.put(("bdone",))
            except Exception as e:  # noqa: BLE001
                self.q.put(("err", f"Evaluasi gagal: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _bench_export(self):
        if not self.bench_rows:
            return messagebox.showinfo("Info", "Belum ada hasil untuk diekspor.")
        p = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="hasil_benchmark.csv",
                                         filetypes=[("CSV", "*.csv")])
        if p:
            metrics.export_csv(self.bench_rows, p)
            self.status.set(f"Hasil diekspor ke {p}")

    def _summarize(self):
        lines = []
        for b in ce.VALID_KEY_BITS:
            rs = [r for r in self.bench_rows if r["kunci_bit"] == b]
            if not rs:
                continue
            avg = lambda k: sum(r[k] for r in rs) / len(rs)
            lines.append(
                f"AES-{b}: throughput enkripsi rata-rata {avg('throughput_enkripsi_MBps'):.2f} MB/s | "
                f"entropi {avg('entropi_bit_per_byte'):.4f} | avalanche {avg('avalanche_persen'):.2f}% | "
                f"CPU {avg('cpu_persen'):.1f}% | RAM {avg('ram_MB'):.0f} MB")
        self.lbl_summary.config(text="\n".join(lines))

    # ------------------------------------------------------------ event loop
    def _poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                kind = m[0]
                if kind == "p":
                    self.prog["value"] = m[1]
                elif kind == "done":
                    _, mode, dst, st = m
                    self.prog["value"] = 100
                    aksi = "Enkripsi" if mode == "encrypt" else "Dekripsi"
                    self._log(
                        f"[{aksi} selesai] AES-{st['key_bits']} ({st['rounds']} ronde)\n"
                        f"  Keluaran     : {dst}\n"
                        f"  Ukuran       : {st['plain_size']:,} B -> {st['enc_size']:,} B "
                        f"(selisih {st['overhead']} B)\n"
                        f"  Waktu KDF    : {st['kdf_time']:.3f} s\n"
                        f"  Waktu proses : {st['crypt_time']:.3f} s "
                        f"({st['throughput']:.2f} MB/s)")
                    self.status.set(f"{aksi} berhasil.")
                    self.busy = False
                    self.btn_run.config(state="normal")
                elif kind == "brow":
                    r, i = m[1], m[2]
                    self.bench_rows.append(r)
                    self.tree.insert("", "end", values=(
                        r["berkas"], f"AES-{r['kunci_bit']}", r["ronde"], r["overhead_byte"],
                        r["throughput_enkripsi_MBps"], r["throughput_dekripsi_MBps"],
                        r["entropi_bit_per_byte"], r["avalanche_persen"], r["cpu_persen"],
                        r["ram_MB"], "Ya" if r["integritas_ok"] else "TIDAK"))
                    self.bprog["value"] = i
                elif kind == "bdone":
                    self._summarize()
                    self.status.set("Evaluasi selesai.")
                    self.busy = False
                    self.btn_bench.config(state="normal")
                elif kind == "err":
                    self.status.set("Gagal.")
                    self._log(f"[GAGAL] {m[1]}")
                    messagebox.showerror("Gagal", m[1])
                    self.busy = False
                    self.btn_run.config(state="normal")
                    self.btn_bench.config(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._poll)


def run():
    App().mainloop()
