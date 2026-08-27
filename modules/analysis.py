# -*- coding: utf-8 -*-
"""Modulo de Analisis de Seguridad & Red."""
import os
import sys
import re
import time
import math
import socket
import hashlib
import base64
import secrets
import string
import urllib.parse
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ui, net
from core import banner as B


def local_net_info():
    ui.banner_line("Info de red local  (sin root)")
    hostname = socket.gethostname()
    ui.item("Hostname", hostname)
    try:                                    # IP de salida via socket UDP (no envia nada)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ui.item("IP local (salida)", s.getsockname()[0]); s.close()
    except Exception:
        ui.item("IP local (salida)", "?")
    try:
        ips = sorted(set(a[4][0] for a in socket.getaddrinfo(hostname, None)))
        ui.item("IPs del host", ", ".join(ips))
    except Exception:
        pass
    try:                                    # gateway por defecto (Linux/Termux)
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                    ui.item("Gateway", gw); break
    except Exception:
        pass
    ui.item("IP publica", net.get_public_ip() or "?")


def public_ip():
    ui.banner_line("IP publica + geolocalizacion")
    ip = net.get_public_ip()
    if not ip:
        ui.bad("No se pudo obtener"); return
    ui.item("IP publica", ip)
    j, _ = net.http_json(f"http://ip-api.com/json/{ip}", timeout=8)
    if j and j.get("status") == "success":
        ui.item("Ubicacion", f"{j.get('city')}, {j.get('regionName')}, {j.get('country')}")
        ui.item("ISP", j.get("isp"))
        ui.item("AS", j.get("as"))


def password_strength():
    ui.banner_line("Analizador de fortaleza de contrasena")
    pw = ui.ask("Contrasena a evaluar:")
    if not pw:
        return
    checks = {
        "minusculas": bool(re.search(r"[a-z]", pw)),
        "mayusculas": bool(re.search(r"[A-Z]", pw)),
        "digitos": bool(re.search(r"\d", pw)),
        "simbolos": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }
    pool = (26 * checks["minusculas"] + 26 * checks["mayusculas"] +
            10 * checks["digitos"] + 33 * checks["simbolos"])
    entropy = len(pw) * math.log2(pool) if pool else 0
    for k, v in checks.items():
        (ui.good if v else ui.bad)(f"{k}: {'si' if v else 'no'}")
    ui.item("Longitud", len(pw))
    ui.item("Entropia aprox", f"{entropy:.1f} bits")
    common = {"123456", "password", "123456789", "qwerty", "111111", "12345678",
              "abc123", "1234567", "password1", "admin", "iloveyou", "000000",
              "qwerty123", "1q2w3e", "dragon", "monkey"}
    if pw.lower() in common:
        ui.bad("APARECE en listas de contrasenas comunes -> muy debil")
    verdict = ("Muy debil" if entropy < 28 else "Debil" if entropy < 40 else
               "Razonable" if entropy < 60 else "Fuerte" if entropy < 80 else "Muy fuerte")
    ui.item("Veredicto", verdict)


def password_gen():
    ui.banner_line("Generador de contrasenas seguras  (secrets)")
    n = ui.ask("Longitud [16]:") or "16"
    try:
        n = int(n)
    except Exception:
        n = 16
    n = max(4, min(n, 256))
    use_sym = (ui.ask("Incluir simbolos? (s/n) [s]:") or "s").lower().startswith("s")
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+[]{};:,.?" if use_sym else "")
    for _ in range(5):
        print(f"   {B.LORANGE}" + "".join(secrets.choice(alphabet) for _ in range(n)) + B.RESET)
    words = ["nova", "cobra", "delta", "raven", "pixel", "orbit", "viper", "lunar",
             "quartz", "matrix", "cipher", "falcon", "photon", "zenith", "onyx", "flux"]
    phrase = "-".join(secrets.choice(words) for _ in range(4)) + str(secrets.randbelow(100))
    ui.item("Passphrase", phrase)


def hash_gen():
    ui.banner_line("Generador de hashes")
    text = ui.ask("Texto:")
    if text == "":
        return
    data = text.encode()
    for algo in ("md5", "sha1", "sha256", "sha512"):
        ui.item(algo, hashlib.new(algo, data).hexdigest())
    ui.item("sha3_256", hashlib.sha3_256(data).hexdigest())
    ui.item("blake2b", hashlib.blake2b(data).hexdigest()[:64])


def hash_id():
    ui.banner_line("Identificador de hashes  (heuristica)")
    h = ui.ask("Hash:")
    if not h:
        return
    h = h.strip()
    L = len(h)
    hexish = bool(re.fullmatch(r"[0-9a-fA-F]+", h))
    guesses = []
    if hexish:
        guesses += {32: ["MD5", "NTLM", "MD4"], 40: ["SHA1", "RIPEMD-160"],
                    56: ["SHA224"], 64: ["SHA256", "SHA3-256", "BLAKE2s"],
                    96: ["SHA384"], 128: ["SHA512", "SHA3-512", "BLAKE2b"]}.get(L, [])
    if h[:4] in ("$2a$", "$2b$", "$2y$"):
        guesses.append("bcrypt")
    if h.startswith("$6$"):
        guesses.append("sha512crypt")
    if h.startswith("$5$"):
        guesses.append("sha256crypt")
    if h.startswith("$1$"):
        guesses.append("md5crypt")
    if h.startswith("$argon2"):
        guesses.append("Argon2")
    if not hexish and re.fullmatch(r"[A-Za-z0-9+/=]+", h) and L % 4 == 0:
        guesses.append("Base64 (posible, no hash)")
    ui.item("Longitud", L)
    ui.item("Posibles", ", ".join(guesses) or "desconocido")


def encoder_decoder():
    ui.banner_line("Encoder / Decoder")
    print(f"   {B.RED}[1]{B.RESET} Base64 enc   {B.RED}[2]{B.RESET} Base64 dec")
    print(f"   {B.RED}[3]{B.RESET} Hex enc      {B.RED}[4]{B.RESET} Hex dec")
    print(f"   {B.RED}[5]{B.RESET} URL enc      {B.RED}[6]{B.RESET} URL dec")
    print(f"   {B.RED}[7]{B.RESET} ROT13")
    op = ui.ask("Op:")
    text = ui.ask("Texto:")
    rot13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    try:
        out = {
            "1": lambda: base64.b64encode(text.encode()).decode(),
            "2": lambda: base64.b64decode(text.encode()).decode("utf-8", "replace"),
            "3": lambda: text.encode().hex(),
            "4": lambda: bytes.fromhex(text).decode("utf-8", "replace"),
            "5": lambda: urllib.parse.quote(text),
            "6": lambda: urllib.parse.unquote(text),
            "7": lambda: text.translate(rot13),
        }.get(op, lambda: None)()
        if out is None:
            ui.bad("Op invalida"); return
        ui.good("Resultado:")
        print(f"   {B.LORANGE}{out}{B.RESET}")
    except Exception as e:
        ui.bad(f"Error: {e}")


def connectivity_test():
    ui.banner_line("Test de conectividad  (TCP)")
    host = ui.ask("Host:")
    if not host:
        return
    ports_s = ui.ask("Puertos coma [enter=80,443]:") or "80,443"
    ports = [int(x) for x in ports_s.split(",") if x.strip().isdigit()]
    ip = net.resolve(host)
    ui.item("Resuelve a", ip or "NO RESUELVE")
    if not ip:
        return
    for p in ports:
        t0 = time.time()
        ok = net.tcp_connect(ip, p, 3.0)
        dt = (time.time() - t0) * 1000
        (ui.good if ok else ui.bad)(
            f"Puerto {p}: {'ABIERTO' if ok else 'cerrado/filtrado'}  ({dt:.0f} ms)")


def http_status():
    ui.banner_line("HTTP Status / Uptime check")
    url = ui.ask("URL:")
    if not url:
        return
    t0 = time.time()
    code, hdrs, body, final = net.http_request(url, timeout=12)
    dt = (time.time() - t0) * 1000
    if code is None:
        ui.bad(f"CAIDO / sin respuesta ({body.decode('utf-8', 'replace')[:80]})"); return
    (ui.good if code < 400 else ui.warn)(f"HTTP {code}  en {dt:.0f} ms")
    ui.item("URL final", final)
    server = None
    for k, v in hdrs.items():
        if k.lower() == "server":
            server = v
    ui.item("Server", server or "-")
    ui.item("Tamano", f"{len(body)} bytes")


def tcp_latency():
    ui.banner_line("TCP Latency  (ping por TCP, sin root)")
    host = ui.ask("Host:")
    if not host:
        return
    port = ui.ask("Puerto [443]:") or "443"
    try:
        port = int(port)
    except Exception:
        port = 443
    ip = net.resolve(host)
    if not ip:
        ui.bad("No resuelve"); return
    ui.info(f"5 sondas TCP a {ip}:{port} ...")
    times = []
    for i in range(5):
        t0 = time.time()
        ok = net.tcp_connect(ip, port, 3.0)
        dt = (time.time() - t0) * 1000
        if ok:
            times.append(dt); print(f"   seq={i + 1}  {dt:.1f} ms")
        else:
            print(f"   seq={i + 1}  timeout")
        time.sleep(0.2)
    if times:
        ui.item("min/avg/max",
                f"{min(times):.1f} / {sum(times) / len(times):.1f} / {max(times):.1f} ms")
    ui.item("Perdida", f"{(5 - len(times)) / 5 * 100:.0f}%")


TOOLS = [
    ("1", "Info de red local", local_net_info),
    ("2", "IP publica + geo", public_ip),
    ("3", "Fortaleza de contrasena", password_strength),
    ("4", "Generador de contrasenas", password_gen),
    ("5", "Generador de hashes", hash_gen),
    ("6", "Identificador de hash", hash_id),
    ("7", "Encoder / Decoder", encoder_decoder),
    ("8", "Test de conectividad", connectivity_test),
    ("9", "HTTP status / uptime", http_status),
    ("10", "TCP latency (ping)", tcp_latency),
]


def menu():
    while True:
        ui.clear()
        ui.menu("ANALISIS SEGURIDAD & RED", [(k, l) for k, l, _ in TOOLS])
        ch = ui.ask("Opcion:")
        if ch in ("0", ""):
            return
        for k, _l, fn in TOOLS:
            if ch == k:
                try:
                    fn()
                except KeyboardInterrupt:
                    print()
                except Exception as e:
                    ui.bad(f"Error: {e}")
                ui.pause()
                break
        else:
            ui.warn("Opcion invalida"); ui.pause()


if __name__ == "__main__":
    menu()
