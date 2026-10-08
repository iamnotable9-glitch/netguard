"""Input validation and safe, bounded subprocess helpers."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass

INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@dataclass
class CommandResult:
    available: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


def valid_interface(name: str) -> bool:
    return bool(INTERFACE_RE.fullmatch(name))


def valid_mac(value: str) -> bool:
    return bool(MAC_RE.fullmatch(value))


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def run_command(
    argv: list[str], *, timeout: float = 6.0, max_output: int = 100_000
) -> CommandResult:
    """Run a fixed argument vector; never invoke a shell or accept shell text."""
    if not argv or not shutil.which(argv[0]):
        return CommandResult(False, error=f"Command not installed: {argv[0] if argv else '(empty)'}")
    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            True,
            result.returncode,
            result.stdout[:max_output],
            result.stderr[:2000],
        )
    except subprocess.TimeoutExpired:
        return CommandResult(True, error=f"Timed out after {timeout:g} seconds.")
    except OSError as exc:
        return CommandResult(True, error=f"Could not run command: {exc}")
