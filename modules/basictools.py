# -*- coding: utf-8 -*-
"""Modulo Toolkit de Seguridad Basica."""
import os
import sys
import math
import uuid
import random
import secrets
import hashlib
import ipaddress
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ui
from core import banner as B


def mac_gen():
    ui.banner_line("Generador de MAC aleatoria")
    n = ui.ask("Cuantas [5]:") or "5"
    try:
        n = int(n)
    except Exception:
        n = 5
    local = (ui.ask("Localmente administrada? (s/n) [s]:") or "s").lower().startswith("s")
    for _ in range(max(1, min(n, 50))):
        mac = [secrets.randbelow(256) for _ in range(6)]
        if local:
            mac[0] = (mac[0] & 0xFC) | 0x02          # bit local=1, unicast=0
        print(f"   {B.LORANGE}" + ":".join(f"{b:02x}" for b in mac) + B.RESET)


def token_gen():
    ui.banner_line("Generador de tokens / UUID  (secrets)")
    ui.item("UUID4", str(uuid.uuid4()))
    ui.item("Hex 16B", secrets.token_hex(16))
    ui.item("Hex 32B", secrets.token_hex(32))
    ui.item("URL-safe", secrets.token_urlsafe(24))
    ui.item("API-key est.", "sk_" + secrets.token_urlsafe(32))
    ui.item("PIN 6", "".join(str(secrets.randbelow(10)) for _ in range(6)))


def file_hash():
    ui.banner_line("Hash de fichero")
    path = ui.ask("Ruta del fichero:")
    if not path:
        return
    if not os.path.isfile(path):
        ui.bad("No existe"); return
    hs = {a: hashlib.new(a) for a in ("md5", "sha1", "sha256")}
    size = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                size += len(chunk)
                for h in hs.values():
                    h.update(chunk)
    except Exception as e:
        ui.bad(f"Error: {e}"); return
    ui.item("Fichero", os.path.basename(path))
    ui.item("Tamano", f"{size} bytes")
    for a, h in hs.items():
        ui.item(a, h.hexdigest())


def text_entropy():
    ui.banner_line("Entropia de Shannon  (texto)")
    text = ui.ask("Texto:")
    if text == "":
        return
    counts = Counter(text)
    total = len(text)
    ent = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
    ui.item("Longitud", total)
    ui.item("Chars unicos", len(counts))
    ui.item("Entropia", f"{ent:.3f} bits/char")
    ui.item("Total aprox", f"{ent * total:.1f} bits")


def cipher_toy():
    ui.banner_line("Cifrados clasicos  (Caesar / XOR / ROT13)")
    print(f"   {B.RED}[1]{B.RESET} Caesar   {B.RED}[2]{B.RESET} XOR (hex out)   {B.RED}[3]{B.RESET} ROT13")
    op = ui.ask("Op:")
    text = ui.ask("Texto:")
    if op == "1":
        try:
            shift = int(ui.ask("Desplazamiento [3]:") or "3")
        except Exception:
            shift = 3
        out = []
        for ch in text:
            if ch.isupper():
                out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            elif ch.islower():
                out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            else:
                out.append(ch)
        ui.good("".join(out))
    elif op == "2":
        key = ui.ask("Clave:")
        if not key:
            ui.bad("Clave vacia"); return
        kb, tb = key.encode(), text.encode()
        out = bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb)))
        ui.good("Hex: " + out.hex())
    elif op == "3":
        ui.good(text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")))
    else:
        ui.bad("Op invalida")


def wordlist_gen():
    ui.banner_line("Generador de wordlist  (combinaciones)")
    base = ui.ask("Palabras base separadas por coma:")
    if not base:
        return
    words = [w.strip() for w in base.split(",") if w.strip()]
    suffixes = ["", "123", "2024", "2025", "!", "01", "007", "@", "1234", "#"]
    leet_map = str.maketrans("aeiosAEIOS", "4310543105")
    caps = set()
    for w in words:
        variants = {w, w.lower(), w.upper(), w.capitalize(), w[::-1], w.translate(leet_map)}
        for v in variants:
            for s in suffixes:
                caps.add(v + s)
    caps = sorted(caps)
    ui.good(f"{len(caps)} candidatos generados (muestra 40):")
    for cnd in caps[:40]:
        print(f"   {B.ORANGE}{cnd}{B.RESET}")
    if (ui.ask("Guardar a wordlist_out.txt? (s/n) [n]:") or "n").lower().startswith("s"):
        with open("wordlist_out.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(caps))
        ui.good(f"Guardado: {os.path.abspath('wordlist_out.txt')} ({len(caps)} lineas)")


UA_TEMPLATES = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{c}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{s}.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:{f}.0) Gecko/20100101 Firefox/{f}.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{c}.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]


def useragent_gen():
    ui.banner_line("Generador de User-Agents")
    for t in UA_TEMPLATES:
        ua = t.format(c=random.randint(118, 130), s=random.randint(16, 18), f=random.randint(118, 130))
        print(f"   {B.GREY}{ua}{B.RESET}")


def subnet_calc():
    ui.banner_line("Calculadora de subred  (CIDR)")
    cidr = ui.ask("Red/CIDR (ej 192.168.1.0/24):")
    if not cidr:
        return
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        ui.bad(f"Invalido: {e}"); return
    ui.item("Red", str(n.network_address))
    ui.item("Mascara", str(n.netmask))
    ui.item("Wildcard", str(n.hostmask))
    ui.item("Broadcast", str(getattr(n, "broadcast_address", "-")))
    ui.item("Prefijo", f"/{n.prefixlen}")
    ui.item("Total IPs", n.num_addresses)
    hosts = list(n.hosts())
    if hosts:
        ui.item("Primer host", str(hosts[0]))
        ui.item("Ultimo host", str(hosts[-1]))
        ui.item("Hosts usables", len(hosts))
    ui.item("Es privada", n.is_private)


TOOLS = [
    ("1", "MAC aleatoria", mac_gen),
    ("2", "Tokens / UUID", token_gen),
    ("3", "Hash de fichero", file_hash),
    ("4", "Entropia de texto", text_entropy),
    ("5", "Cifrados clasicos", cipher_toy),
    ("6", "Generador de wordlist", wordlist_gen),
    ("7", "Generador de User-Agents", useragent_gen),
    ("8", "Calculadora de subred", subnet_calc),
]


def menu():
    while True:
        ui.clear()
        ui.menu("TOOLKIT SEGURIDAD BASICA", [(k, l) for k, l, _ in TOOLS])
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
