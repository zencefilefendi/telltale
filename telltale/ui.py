"""
TELLTALE — zero-dependency terminal UI.

No rich, no colorama, no install step. A SOC box, a Raspberry Pi at the edge, or a
locked-down analyst laptop can all run `python3 -m telltale demo` and get the same
output. Honors NO_COLOR and non-TTY pipes.
"""

from __future__ import annotations

import os
import sys

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_CODES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "ital": "\033[3m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "white": "\033[97m", "grey": "\033[90m",
    "bred": "\033[91m", "bgreen": "\033[92m", "byellow": "\033[93m",
    "bcyan": "\033[96m", "bmagenta": "\033[95m",
    "onred": "\033[41m\033[97m", "onyellow": "\033[43m\033[30m",
    "ongreen": "\033[42m\033[30m", "onblue": "\033[44m\033[97m",
}


def set_color(on: bool) -> None:
    global _USE_COLOR
    _USE_COLOR = on


def c(text: str, *styles: str) -> str:
    if not _USE_COLOR:
        return text
    pre = "".join(_CODES.get(s, "") for s in styles)
    return f"{pre}{text}{_CODES['reset']}" if pre else text


def hr(char: str = "─", width: int = 74, style: str = "grey") -> str:
    return c(char * width, style)


def banner() -> str:
    art = r"""
 ╔════════════════════════════════════════════════════════════════════════╗
 ║   T E L L T A L E                                                       ║
 ║   passive zero-click / Pegasus-class implant detection for the wire    ║
 ║   "the endpoint lies — the wire remembers"                             ║
 ╚════════════════════════════════════════════════════════════════════════╝"""
    return c(art, "bcyan", "bold")


def badge(verdict: str) -> str:
    style = {
        "CRITICAL": "onred", "HIGH": "onyellow", "ELEVATED": "byellow",
        "WATCH": "cyan", "BENIGN": "green",
    }.get(verdict, "white")
    return c(f" {verdict} ", style, "bold")


def riskbar(score: float, width: int = 24) -> str:
    filled = int(round(score / 100.0 * width))
    style = "bred" if score >= 80 else "byellow" if score >= 60 else \
        "yellow" if score >= 40 else "cyan" if score >= 20 else "green"
    return c("█" * filled, style) + c("░" * (width - filled), "grey")


def kv(key: str, val: str, key_w: int = 16) -> str:
    return f"  {c(key.ljust(key_w), 'grey')} {val}"


def section(title: str) -> str:
    return "\n" + c(f"▎ {title}", "bold", "white") + "\n" + hr()
