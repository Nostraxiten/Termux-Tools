# -*- coding: utf-8 -*-
"""
Banner y paleta de color (naranja -> rojo) para Termux-Tool.
Todo con codigos ANSI 256, sin dependencias.
"""
import shutil

# ---- estilos base ----
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"

# ---- paleta rojo -> naranja -> ambar ----
GRAD    = [196, 202, 208, 214, 220]     # gradiente de arriba (rojo) a abajo (ambar)
RED     = "\033[38;5;196m"
DRED    = "\033[38;5;160m"
ORANGE  = "\033[38;5;208m"
LORANGE = "\033[38;5;214m"
AMBER   = "\033[38;5;220m"
GREEN   = "\033[38;5;46m"
GREY    = "\033[38;5;244m"
WHITE   = "\033[38;5;255m"


def c(code):
    """Devuelve un codigo de color ANSI 256 arbitrario."""
    return f"\033[38;5;{code}m"


# ---- murcielago (generado a partir de una silueta real, 52 cols) ----
BAT = r"""
              ░▒░                  ░▒░
        ░▓▓▓▓▓█▒     ▒        ▒     ░█▓▓▓▓▓░
      ▒█████████▒    ██▓    ▒██    ▒█████████▒
    ▒████████████▓   ▓█████████   ▓████████████▒
   ████████████████▓░░████████░░▓████████████████
 ░████████████████████████████████████████████████░
 ▒   ▒████████████████████████████████████████▒   ▒
      ▒█▒░▒▓████████████████████████████▓▒░▒█▒
             ▓█████████████████████████░
              ▓▒░▒▓██████████████▓▒░▒█
                    ▓██████████▓
                     ▓█████████
                        ████░
                        ▓▓█▓░
                         ░█
                          ░
"""

# ---- murcielago compacto (34 cols, terminales estrechas) ----
BAT_COMPACT = r"""
         ▒░            ░▒
    ▒█████▓   █░  ░█░  ▒█████▒
  ░█████████░ ▓████▓ ░▓████████░
 ▓██████████████████████████████▓
░   ██████████████████████████
        ▒████████████████▒
         ░  ▒████████▒  ░
              ▓████▓
               ░██▒
                 ▓
"""

# ---- "TERMUX" en bloque 3D (estilo ANSI Shadow) ----
BIG = r"""
████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║╚██╗██╔╝
   ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║ ╚███╔╝
   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║ ██╔██╗
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"""

# ---- fallback compacto para terminales estrechas (moviles) ----
COMPACT = r"""
 _____                       _____         _
|_   _|___ _ _ _ __  _ _ _ _|_   _|___  ___| |
  | |/ -_) '_| '  \| || \ \ / | |/ _ \/ _ \ |
  |_|\___|_| |_|_|_|\_,_/_\_\ |_|\___/\___/_|
"""


def _grad_block(text):
    """Colorea un bloque multilinea con el gradiente rojo->ambar por filas."""
    lines = text.split("\n")
    out, n = [], max(1, len(lines))
    for i, line in enumerate(lines):
        idx = min(int(i * len(GRAD) / n), len(GRAD) - 1)
        out.append(c(GRAD[idx]) + line + RESET)
    return "\n".join(out)


def _center(text, width):
    return f"{text:^{width}}"


def print_banner():
    """Imprime el banner completo, adaptando el tamano al ancho del terminal."""
    width = shutil.get_terminal_size((80, 24)).columns
    w = max(width, 56)
    print()
    if width >= 56:
        print(_grad_block(BAT))
        print(BOLD + _grad_block(BIG) + RESET)
        print(f"{ORANGE}{BOLD}{_center('▓▒░  T · O · O · L  ░▒▓', w)}{RESET}")
    else:
        print(_grad_block(BAT_COMPACT))
        print(BOLD + _grad_block(COMPACT) + RESET)
    tagline = "Offensive Recon · OSINT · Scanning · Security Analysis"
    author  = "by nostraxiten · 100% Python stdlib · Termux/Kali · no-root"
    print(f"{LORANGE}{_center(tagline, w)}{RESET}")
    print(f"{GREY}{_center(author, w)}{RESET}")
    print(f"{DRED}{_center('─' * min(width, 66), w)}{RESET}")
    print()
