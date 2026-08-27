#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Termux-Tool  ·  Framework ofensivo de recon / OSINT / scanning / analisis
Autor: nostraxiten  ·  github.com/nostraxiten

100% Python stdlib · Termux/Kali · sin root · sin binarios externos.
Los protocolos (DNS, WHOIS, TCP, TLS, HTTP) se hablan a mano con sockets.
"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

try:
    from core import ui
    from core import banner as B
    from modules import osint, passive, active, analysis, basictools
except Exception as e:
    print("Error importando modulos:", e)
    print("Ejecuta el script desde su carpeta:  python termux-tool.py")
    sys.exit(1)


MAIN = [
    ("1", "OSINT & Reconocimiento", osint.menu),
    ("2", "Escaneo Pasivo", passive.menu),
    ("3", "Escaneo Activo / Agresivo", active.menu),
    ("4", "Analisis Seguridad & Red", analysis.menu),
    ("5", "Toolkit Seguridad Basica", basictools.menu),
    ("6", "Acerca de / Info", None),
]

ABOUT = """
Termux-Tool reune 47 utilidades en 5 categorias, todo en Python puro (stdlib):

  [1] OSINT      -> IP/GEO, WHOIS, DNS propio, SSL, GitHub, Wayback, phone, users
  [2] Pasivo     -> crt.sh subdominios, robots, security.txt, headers, cookies, CMS
  [3] Activo     -> port scan, host sweep, dir/subdomain brute, vhost, crawler
  [4] Analisis   -> fortaleza pw, hashes, encoders, latencia, status, red local
  [5] Basico     -> MAC/tokens/UUID, hash de ficheros, entropia, cifrados, wordlists

Sin root y sin nmap/whois/dig externos: DNS, WHOIS, TCP, TLS y HTTP estan
implementados a mano con sockets/ssl/urllib. Compatible con Termux 100% y Kali.

  Uso legal: escanea SOLO sistemas propios o con permiso explicito.
"""


def about():
    ui.clear()
    ui.title("ACERCA DE Termux-Tool")
    print(B.LORANGE + ABOUT + B.RESET)
    ui.pause()


def main():
    while True:
        ui.clear()
        B.print_banner()
        ui.menu("MENU PRINCIPAL", [(k, l) for k, l, _ in MAIN], back_label="Salir")
        ch = ui.ask("Selecciona modulo:")
        if ch in ("0", ""):
            print(f"\n{B.ORANGE}Hasta luego, nostraxiten.{B.RESET}\n")
            return
        if ch == "6":
            about()
            continue
        for k, _l, fn in MAIN:
            if ch == k and fn:
                try:
                    fn()
                except KeyboardInterrupt:
                    print()
                break
        else:
            ui.warn("Opcion invalida")
            ui.pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{B.ORANGE}Interrumpido. Bye.{B.RESET}")
