# -*- coding: utf-8 -*-
"""Utilidades de interfaz: menus, prompts y salida con color."""
import os
from core import banner as B


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def rule(width=66, ch="─"):
    print(B.DRED + ch * width + B.RESET)


def title(text):
    line = "═" * (len(text) + 4)
    print(f"{B.ORANGE}╔{line}╗{B.RESET}")
    print(f"{B.ORANGE}║  {B.BOLD}{B.LORANGE}{text}{B.RESET}{B.ORANGE}  ║{B.RESET}")
    print(f"{B.ORANGE}╚{line}╝{B.RESET}")


def menu(header, options, back_label="Volver"):
    """options: lista de tuplas (clave, etiqueta)."""
    title(header)
    for key, label in options:
        print(f"  {B.RED}[{B.LORANGE}{key:>2}{B.RED}]{B.RESET} {B.WHITE}{label}{B.RESET}")
    print(f"  {B.RED}[{B.LORANGE} 0{B.RED}]{B.RESET} {B.GREY}{back_label}{B.RESET}")
    rule()


def ask(prompt):
    try:
        return input(
            f"{B.ORANGE}┌─[{B.LORANGE}Termux-Tool{B.ORANGE}]{B.RESET}\n"
            f"{B.ORANGE}└──╼ {B.LORANGE}{prompt}{B.RESET} "
        ).strip()
    except EOFError:
        return ""


def info(msg): print(f"{B.LORANGE}[*]{B.RESET} {msg}")
def good(msg): print(f"{B.GREEN}[+]{B.RESET} {msg}")
def bad(msg):  print(f"{B.RED}[-]{B.RESET} {msg}")
def warn(msg): print(f"{B.AMBER}[!]{B.RESET} {msg}")
def item(k, v): print(f"   {B.ORANGE}{str(k):<18}{B.RESET}: {B.WHITE}{v}{B.RESET}")


def banner_line(msg):
    print(f"\n{B.DRED}▚▚▚{B.RESET} {B.BOLD}{B.LORANGE}{msg}{B.RESET} {B.DRED}▚▚▚{B.RESET}\n")


def pause():
    try:
        input(f"\n{B.GREY}[ Enter para continuar ]{B.RESET}")
    except EOFError:
        pass
