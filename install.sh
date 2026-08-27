#!/usr/bin/env bash
# Termux-Tool - setup (no requiere root)
set -e
echo "[*] Termux-Tool - preparando entorno..."

if command -v pkg >/dev/null 2>&1; then
    # Termux
    pkg install -y python
elif command -v apt >/dev/null 2>&1; then
    # Debian / Kali
    sudo apt update && sudo apt install -y python3
fi

chmod +x termux-tool.py 2>/dev/null || true
echo "[+] Listo. No hay dependencias pip: todo es stdlib."
echo "[+] Ejecuta:"
echo "      python termux-tool.py"
