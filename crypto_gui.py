#!/usr/bin/env python3
"""
Crypto Toolkit GUI
X25519 ECDH · AES-256-GCM · Ed25519 · Argon2id
Single-file Windows executable (compile with PyInstaller).

Build (on Windows):
    pip install cryptography argon2-cffi pyinstaller
    pyinstaller crypto_gui.py --onefile --windowed --name CryptoToolkit
"""

from __future__ import annotations

import base64
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

# ── crypto primitives ─────────────────────────────────────────────────────────

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

try:
    from argon2.low_level import hash_secret_raw
except ImportError:
    sys.exit("Error: argon2-cffi required. Run: pip install argon2-cffi")

# ── constants ─────────────────────────────────────────────────────────────────

ARGON2_SALT_LEN     = 16
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST  = 65536   # KB
ARGON2_PARALLELISM  = 4
ARGON2_HASH_LEN     = 32
HKDF_INFO           = b"crypto-toolkit-v1"
AES_NONCE_LEN       = 12
AES_KEY_LEN         = 32

# ── crypto helpers ────────────────────────────────────────────────────────────

def _argon2id_raw(secret: bytes, salt: bytes) -> bytes:
    from argon2.low_level import Type
    return hash_secret_raw(
        secret=secret, salt=salt,
        time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

def hkdf_derive(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=AES_KEY_LEN,
        salt=b"", info=HKDF_INFO
    ).derive(shared_secret)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(AES_NONCE_LEN)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct_tag   # nonce(12) || ciphertext || tag(16)

def aes_decrypt(key: bytes, data: bytes) -> bytes:
    nonce  = data[:AES_NONCE_LEN]
    ct_tag = data[AES_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct_tag, None)

# ── PEM helpers ───────────────────────────────────────────────────────────────

def _b64_pem(block_type: str, body: bytes) -> str:
    b64 = base64.b64encode(body).decode()
    lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {block_type}-----\n{lines}\n-----END {block_type}-----\n"

def _write_pem(path: str, pem_text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(pem_text)

def _read_pem(path: str, block_type: str) -> bytes:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    b64 = "".join(
        l for l in content.split("\n")
        if l and not l.startswith("-----")
    )
    return base64.b64decode(b64)

# ── key I/O ───────────────────────────────────────────────────────────────────

def _encrypt_payload(payload: bytes, password: str) -> bytes:
    salt  = os.urandom(ARGON2_SALT_LEN)
    nonce = os.urandom(AES_NONCE_LEN)
    key   = _argon2id_raw(password.encode(), salt)
    ct    = AESGCM(key).encrypt(nonce, payload, None)
    return salt + nonce + ct    # salt(16) || nonce(12) || ct_tag

def _decrypt_payload(data: bytes, password: str) -> bytes:
    salt   = data[:ARGON2_SALT_LEN]
    nonce  = data[ARGON2_SALT_LEN : ARGON2_SALT_LEN + AES_NONCE_LEN]
    ct_tag = data[ARGON2_SALT_LEN + AES_NONCE_LEN:]
    key    = _argon2id_raw(password.encode(), salt)
    return AESGCM(key).decrypt(nonce, ct_tag, None)

def save_x25519(name: str, priv: X25519PrivateKey, pub: X25519PublicKey,
                password: str) -> None:
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw  = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    _write_pem(
        f"{name}_private.pem",
        _b64_pem("ENCRYPTED X25519 PRIVATE KEY",
                 _encrypt_payload(priv_raw, password))
    )
    _write_pem(f"{name}_public.pem",
               _b64_pem("X25519 PUBLIC KEY", pub_raw))

def save_ed25519(name: str, priv: Ed25519PrivateKey, pub: Ed25519PublicKey,
                 password: str) -> None:
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw  = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    _write_pem(
        f"{name}_sign_private.pem",
        _b64_pem("ENCRYPTED ED25519 PRIVATE KEY",
                 _encrypt_payload(priv_raw, password))
    )
    _write_pem(f"{name}_sign_public.pem",
               _b64_pem("ED25519 PUBLIC KEY", pub_raw))

def load_x25519_private(path: str, password: str) -> X25519PrivateKey:
    raw = _decrypt_payload(_read_pem(path, "ENCRYPTED X25519 PRIVATE KEY"), password)
    return X25519PrivateKey.from_private_bytes(raw)

def load_x25519_public(path: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(
        _read_pem(path, "X25519 PUBLIC KEY"))

def load_ed25519_private(path: str, password: str) -> Ed25519PrivateKey:
    raw = _decrypt_payload(_read_pem(path, "ENCRYPTED ED25519 PRIVATE KEY"), password)
    return Ed25519PrivateKey.from_private_bytes(raw)

def load_ed25519_public(path: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(
        _read_pem(path, "ED25519 PUBLIC KEY"))


# ════════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ════════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    BG      = "#1a1a2e"
    FG      = "#e0e0e0"
    ACCENT  = "#4fc3f7"
    ACCENT2 = "#81c784"
    ERROR   = "#ef5350"

    def __init__(self) -> None:
        super().__init__()
        self.title(
            "Crypto Toolkit  |  X25519 · AES-256-GCM · Ed25519 · Argon2id")
        self.configure(bg=self.BG)
        self.geometry("720x740")
        self.minsize(600, 600)
        self._style()

        # ── header ──
        hdr = tk.Frame(self, bg=self.BG)
        hdr.pack(fill="x", padx=24, pady=(18, 4))
        tk.Label(hdr, text="🛡  Crypto Toolkit",
                 bg=self.BG, fg=self.ACCENT,
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(hdr,
                 text="X25519 ECDH  ·  AES-256-GCM  ·  Ed25519  ·  Argon2id",
                 bg=self.BG, fg="#888",
                 font=("Segoe UI", 9)).pack(anchor="w")

        # ── notebook ──
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=15, pady=(4, 15))
        nb.add(self._tab_keys(),    text="  🔑  Generar Claves")
        nb.add(self._tab_encrypt(), text="  🔒  Cifrar Archivo")
        nb.add(self._tab_decrypt(), text="  🔓  Descifrar Archivo")
        nb.add(self._tab_sign(),    text="  ✍   Firmar / Verificar")
        nb.add(self._tab_derive(),  text="  🔑  Derivar desde Contraseña")

    def _style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        for cls in ("TFrame","TLabelframe","TLabelframe.Label",
                    "TLabel","TButton","TEntry","TSeparator"):
            s.configure(cls, background=self.BG, foreground=self.FG)
        s.configure("TButton", padding=9, relief="flat",
                    background=self.ACCENT, foreground="#1a1a2e",
                    font=("Segoe UI", 10, "bold"))
        s.map("TButton", background=[("active", "#29b6f6")])

    # ── helpers ──────────────────────────────────────────────────────────────

    def _log(self, text_widget: tk.Text, msg: str, ok: bool = True) -> None:
        color = self.ACCENT if ok else self.ERROR
        text_widget.configure(state="normal")
        text_widget.tag_configure("c", foreground=color)
        text_widget.insert("end", msg + "\n", "c")
        text_widget.see("end")
        text_widget.configure(state="disabled")

    def _file_btn(self, entry: ttk.Entry) -> None:
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _save_btn(self, entry: ttk.Entry, def_ext: str) -> None:
        path = filedialog.asksaveasfilename(defaultextension=def_ext)
        if path:
            entry.delete(0, "end")
            entry.insert(0, path)

    def _field(self, parent: ttk.Frame, label: str,
               row: int, browse_btn: Callable | None = None,
               default: str = "", show: str = "") -> ttk.Entry:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="e", padx=8, pady=7)
        e = ttk.Entry(parent, width=44, font=("Segoe UI", 10), show=show)
        e.insert(0, default)
        e.grid(row=row, column=1, sticky="ew", pady=7)
        if browse_btn:
            ttk.Button(parent, text="📁",
                       command=lambda: browse_btn(e)).grid(
                           row=row, column=2, padx=(3, 0))
        parent.columnconfigure(1, weight=1)
        return e

    def _pass_field(self, parent: ttk.Frame, label: str, row: int) -> tuple[ttk.Entry, ttk.Entry]:
        ttk.Label(parent, text=label).grid(
            row=row, column=0, sticky="e", padx=8, pady=7)
        e1 = ttk.Entry(parent, show="●", width=22, font=("Segoe UI", 10))
        e1.grid(row=row, column=1, sticky="w", pady=7)
        ttk.Label(parent, text="Confirmar:").grid(
            row=row, column=1, sticky="e", padx=(90, 8), pady=7)
        e2 = ttk.Entry(parent, show="●", width=22, font=("Segoe UI", 10))
        e2.grid(row=row, column=2, sticky="w", padx=(3, 0))
        parent.columnconfigure(1, weight=1)
        return e1, e2

    def _log_widget(self, parent: ttk.Frame, row: int) -> tk.Text:
        t = tk.Text(parent, height=9, bg="#0d0d1a",
                    font=("Consolas", 9), relief="flat",
                    state="disabled", wrap="word")
        t.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        return t

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB: Keys
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_keys(self) -> ttk.Frame:
        f = ttk.Frame(self, padding=22)
        lf1 = ttk.LabelFrame(f, text="  Claves X25519 (Intercambio ECDH)  ")
        lf1.pack(fill="x", pady=(0, 14))
        ia = ttk.Frame(lf1, padding=(0, 12, 0, 4))
        ia.pack(fill="x")

        self._k_name, self._k_pass, self._k_pass2 = None, None, None  # type: ignore

        r = 0
        ttk.Label(ia, text="Nombre:").grid(row=r, column=0, sticky="e", padx=6, pady=5)
        e = ttk.Entry(ia, width=28, font=("Segoe UI", 10)); e.insert(0, "alice")
        e.grid(row=r, column=1, sticky="w", pady=5); r += 1
        p1, p2 = self._pass_field(ia, "Contraseña:", r)
        self._k_name, self._k_pass, self._k_pass2 = e, p1, p2; r += 1
        ttk.Button(ia, text="🔑  Generar par X25519",
                   command=self._do_x25519).grid(
                       row=r, column=0, columnspan=3, pady=12)

        lf2 = ttk.LabelFrame(f, text="  Claves Ed25519 (Firma Digital)  ")
        lf2.pack(fill="x", pady=(0, 14))
        ib = ttk.Frame(lf2, padding=(0, 12, 0, 4))
        ib.pack(fill="x")
        r = 0
        ttk.Label(ib, text="Nombre:").grid(row=r, column=0, sticky="e", padx=6, pady=5)
        e2 = ttk.Entry(ib, width=28, font=("Segoe UI", 10)); e2.insert(0, "alice")
        e2.grid(row=r, column=1, sticky="w", pady=5); r += 1
        p3, p4 = self._pass_field(ib, "Contraseña:", r)
        self._s_name, self._s_pass, self._s_pass2 = e2, p3, p4; r += 1
        ttk.Button(ib, text="✍  Generar par Ed25519",
                   command=self._do_ed25519).grid(
                       row=r, column=0, columnspan=3, pady=12)

        self._log_keys = self._log_widget(f, 3)
        return f

    def _do_x25519(self) -> None:
        name = self._k_name.get().strip()
        pw1  = self._k_pass.get()
        pw2  = self._k_pass2.get()
        if not name or not pw1:
            messagebox.showerror("Error", "Nombre y contraseña obligatorios.")
            return
        if pw1 != pw2:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return
        try:
            priv = X25519PrivateKey.generate()
            save_x25519(name, priv, priv.public_key(), pw1)
            self._log(self._log_keys,
                f"✅ X25519 creado para '{name}':\n"
                f"   Privada: {name}_private.pem  (cifrada Argon2id)\n"
                f"   Pública: {name}_public.pem\n"
                f"   Carpeta: {os.getcwd()}", ok=True)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _do_ed25519(self) -> None:
        name = self._s_name.get().strip()
        pw1  = self._s_pass.get()
        pw2  = self._s_pass2.get()
        if not name or not pw1:
            messagebox.showerror("Error", "Nombre y contraseña obligatorios.")
            return
        if pw1 != pw2:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            return
        try:
            priv = Ed25519PrivateKey.generate()
            save_ed25519(name, priv, priv.public_key(), pw1)
            self._log(self._log_keys,
                f"✅ Ed25519 creado para '{name}':\n"
                f"   Privada: {name}_sign_private.pem  (cifrada Argon2id)\n"
                f"   Pública: {name}_sign_public.pem\n"
                f"   Carpeta: {os.getcwd()}", ok=True)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB: Encrypt
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_encrypt(self) -> ttk.Frame:
        f = ttk.Frame(self, padding=22)
        lf = ttk.LabelFrame(f,
            text="  Cifrar archivo — X25519 ECDH → AES-256-GCM  ")
        lf.pack(fill="x", pady=(0, 14))
        g = ttk.Frame(lf, padding=(0, 14, 0, 4))
        g.pack(fill="x")

        self._e_my_priv   = self._field(g, "Mi clave privada X25519:", 0,
                                          lambda e: self._file_btn(e))
        self._e_their_pub = self._field(g, "Clave pública del otro:", 1,
                                          lambda e: self._file_btn(e))
        self._e_in        = self._field(g, "Archivo a cifrar:", 2,
                                          lambda e: self._file_btn(e))
        self._e_out       = self._field(g, "Archivo cifrado (output):", 3,
                                          lambda e: self._save_btn(e, ".enc"),
                                          default="archivo.enc")
        self._e_pass      = self._field(g, "Contraseña clave privada:", 4, show="●")

        ttk.Button(g, text="🔒  CIFRAR",
                   command=self._do_encrypt).grid(
                       row=5, column=0, columnspan=3, pady=16)

        self._log_enc = self._log_widget(f, 2)
        return f

    def _do_encrypt(self) -> None:
        my_priv   = self._e_my_priv.get().strip()
        their_pub = self._e_their_pub.get().strip()
        inp       = self._e_in.get().strip()
        out       = self._e_out.get().strip()
        pw        = self._e_pass.get()
        if not all([my_priv, their_pub, inp, out, pw]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
        try:
            priv = load_x25519_private(my_priv, pw)
            pub  = load_x25519_public(their_pub)
            key  = hkdf_derive(priv.exchange(pub))
            with open(inp, "rb") as fh:
                pt = fh.read()
            ct = aes_encrypt(key, pt)
            with open(out, "wb") as fh:
                fh.write(ct)
            self._log(self._log_enc,
                f"✅ Cifrado exitoso\n"
                f"   Origen : {inp}  ({len(pt):,} bytes)\n"
                f"   Destino: {out}  ({len(ct):,} bytes)\n"
                f"   ECDH → HKDF-SHA256 → AES-256-GCM (autenticado)", ok=True)
        except Exception as ex:
            messagebox.showerror("Error de cifrado", str(ex))

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB: Decrypt
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_decrypt(self) -> ttk.Frame:
        f = ttk.Frame(self, padding=22)
        lf = ttk.LabelFrame(f,
            text="  Descifrar archivo — AES-256-GCM → X25519 ECDH  ")
        lf.pack(fill="x", pady=(0, 14))
        g = ttk.Frame(lf, padding=(0, 14, 0, 4))
        g.pack(fill="x")

        self._d_my_priv   = self._field(g, "Mi clave privada X25519:", 0,
                                          lambda e: self._file_btn(e))
        self._d_their_pub  = self._field(g, "Clave pública del otro:", 1,
                                          lambda e: self._file_btn(e))
        self._d_in         = self._field(g, "Archivo cifrado (.enc):", 2,
                                          lambda e: self._file_btn(e))
        self._d_out        = self._field(g, "Archivo descifrado (output):", 3,
                                          lambda e: self._save_btn(e, ""))
        self._d_pass       = self._field(g, "Contraseña clave privada:", 4, show="●")

        ttk.Button(g, text="🔓  DESCIFRAR",
                   command=self._do_decrypt).grid(
                       row=5, column=0, columnspan=3, pady=16)

        self._log_dec = self._log_widget(f, 2)
        return f

    def _do_decrypt(self) -> None:
        my_priv   = self._d_my_priv.get().strip()
        their_pub  = self._d_their_pub.get().strip()
        inp       = self._d_in.get().strip()
        out       = self._d_out.get().strip()
        pw        = self._d_pass.get()
        if not all([my_priv, their_pub, inp, out, pw]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
        try:
            priv = load_x25519_private(my_priv, pw)
            pub  = load_x25519_public(their_pub)
            key  = hkdf_derive(priv.exchange(pub))
            with open(inp, "rb") as fh:
                ct = fh.read()
            pt = aes_decrypt(key, ct)
            with open(out, "wb") as fh:
                fh.write(pt)
            self._log(self._log_dec,
                f"✅ Descifrado exitoso\n"
                f"   Origen : {inp}  ({len(ct):,} bytes)\n"
                f"   Destino: {out}  ({len(pt):,} bytes)\n"
                f"   AES-256-GCM verificado — sin manipulación detectada.", ok=True)
        except Exception:
            messagebox.showerror(
                "Error de descifrado",
                "Clave incorrecta, archivo manipulado o corrupto.\n"
                "Verifica que usas la clave pública del remitente.")

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB: Sign / Verify
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_sign(self) -> ttk.Frame:
        f = ttk.Frame(self, padding=22)

        # Sign
        lf1 = ttk.LabelFrame(f, text="  ✍  Firmar archivo (Ed25519)  ")
        lf1.pack(fill="x", pady=(0, 14))
        g1 = ttk.Frame(lf1, padding=(0, 14, 0, 4))
        g1.pack(fill="x")

        self._si_priv = self._field(g1, "Clave privada de firma:", 0,
                                      lambda e: self._file_btn(e))
        self._si_in   = self._field(g1, "Archivo a firmar:", 1,
                                      lambda e: self._file_btn(e))
        self._si_out  = self._field(g1, "Firma output (.sig):", 2,
                                      lambda e: self._save_btn(e, ".sig"),
                                      default="archivo.sig")
        self._si_pass = self._field(g1, "Contraseña:", 3, show="●")
        ttk.Button(g1, text="✍  FIRMAR",
                   command=self._do_sign).grid(
                       row=4, column=0, columnspan=3, pady=14)

        # Verify
        lf2 = ttk.LabelFrame(f, text="  ✅  Verificar firma (Ed25519)  ")
        lf2.pack(fill="x", pady=(0, 14))
        g2 = ttk.Frame(lf2, padding=(0, 14, 0, 4))
        g2.pack(fill="x")

        self._ve_pub  = self._field(g2, "Clave pública del firmante:", 0,
                                     lambda e: self._file_btn(e))
        self._ve_in   = self._field(g2, "Archivo original:", 1,
                                     lambda e: self._file_btn(e))
        self._ve_sig  = self._field(g2, "Archivo de firma (.sig):", 2,
                                     lambda e: self._file_btn(e))
        ttk.Button(g2, text="✅  VERIFICAR",
                   command=self._do_verify).grid(
                       row=3, column=0, columnspan=3, pady=14)

        self._log_sig = self._log_widget(f, 3)
        return f

    def _do_sign(self) -> None:
        kp  = self._si_priv.get().strip()
        inp = self._si_in.get().strip()
        out = self._si_out.get().strip()
        pw  = self._si_pass.get()
        if not all([kp, inp, out, pw]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
        try:
            priv = load_ed25519_private(kp, pw)
            with open(inp, "rb") as fh:
                data = fh.read()
            sig = priv.sign(data)
            with open(out, "wb") as fh:
                fh.write(sig)
            self._log(self._log_sig,
                f"✅ Firma creada (Ed25519)\n"
                f"   Archivo: {inp}\n"
                f"   Firma  : {out}  ({len(sig)} bytes)", ok=True)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _do_verify(self) -> None:
        pub_path = self._ve_pub.get().strip()
        inp      = self._ve_in.get().strip()
        sig_path = self._ve_sig.get().strip()
        if not all([pub_path, inp, sig_path]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return
        try:
            pub = load_ed25519_public(pub_path)
            with open(inp,      "rb") as fh:
                data = fh.read()
            with open(sig_path, "rb") as fh:
                sig = fh.read()
            pub.verify(sig, data)
            self._log(self._log_sig,
                "✅ FIRMA VÁLIDA — el archivo no fue alterado\n"
                "   y fue firmado con la clave privada correspondiente.", ok=True)
        except Exception:
            self._log(self._log_sig,
                "❌ FIRMA INVÁLIDA — archivo manipulado o\n"
                "   la clave pública no corresponde al firmante.", ok=False)

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB: Derive
    # ─────────────────────────────────────────────────────────────────────────
    def _tab_derive(self) -> ttk.Frame:
        f = ttk.Frame(self, padding=22)
        lf = ttk.LabelFrame(f,
            text="  Derivar clave de 256-bit desde contraseña (Argon2id)  ")
        lf.pack(fill="x", pady=(0, 14))
        g = ttk.Frame(lf, padding=(0, 16, 0, 4))
        g.pack(fill="x")

        self._dr_pass = self._field(g, "Contraseña:", 0, show="●")
        self._dr_salt = self._field(g,
            "Sal (hex, 32 chars, o vacía→random):", 1, default="")
        ttk.Button(g, text="🔑  DERIVAR CLAVE",
                   command=self._do_derive).grid(
                       row=2, column=0, columnspan=3, pady=16)

        self._log_dr = self._log_widget(f, 2)
        return f

    def _do_derive(self) -> None:
        pw   = self._dr_pass.get()
        salt = self._dr_salt.get().strip()
        if not pw:
            messagebox.showerror("Error", "La contraseña es obligatoria.")
            return
        try:
            if salt:
                sb = bytes.fromhex(salt)
                if len(sb) != ARGON2_SALT_LEN:
                    messagebox.showerror("Error",
                        f"La sal debe ser {ARGON2_SALT_LEN} bytes "
                        f"({ARGON2_SALT_LEN*2} hex chars).")
                    return
            else:
                sb = os.urandom(ARGON2_SALT_LEN)
            key = _argon2id_raw(pw.encode(), sb)
            self._log(self._log_dr,
                f"✅ Clave derivada (Argon2id)\n"
                f"   Clave (hex):\n{key.hex()}\n"
                f"   Sal (hex)   : {sb.hex()}\n"
                f"   Params: mem=64MB  iter=3  paralelismo=4\n"
                f"   ⚠  Guarda la sal junto con la clave si la necesitas después.", ok=True)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    App().mainloop()
