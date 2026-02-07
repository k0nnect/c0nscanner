"""terminal color utilities for c0nscanner."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# custom theme with lowercase aesthetic
_theme = Theme({
    "banner": "bold cyan",
    "info": "dim white",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "debug": "dim cyan",
    "param": "bold magenta",
    "url": "underline cyan",
    "payload": "dim green",
    "header": "bold white",
    "divider": "dim white",
})

console = Console(theme=_theme)


def print_banner(text: str) -> None:
    console.print(text, style="banner")


def print_info(text: str) -> None:
    console.print(f"  [info][*][/info] {text}")


def print_success(text: str) -> None:
    console.print(f"  [success][+][/success] {text}")


def print_warning(text: str) -> None:
    console.print(f"  [warning][!][/warning] {text}")


def print_error(text: str) -> None:
    console.print(f"  [error][-][/error] {text}")


def print_critical(text: str) -> None:
    console.print(f"  [critical][!!!][/critical] {text}")


def print_debug(text: str) -> None:
    console.print(f"  [debug][d][/debug] {text}")


def print_finding(severity: str, text: str) -> None:
    style_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    style = style_map.get(severity.lower(), "info")
    console.print(f"  [{style}][{severity.upper()}][/{style}] {text}")


def print_divider() -> None:
    console.print("  " + "-" * 60, style="divider")


def print_header(text: str) -> None:
    console.print(f"\n  [header]{text}[/header]")
    print_divider()
