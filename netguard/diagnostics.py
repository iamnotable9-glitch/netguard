from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .platform_info import PlatformInfo
from .safe import run_command, valid_ip


def collect_diagnostics(info: PlatformInfo) -> dict[str, str]:
    output: dict[str, str] = {}
    if info.interfaces:
        output["Interfaces"] = ", ".join(info.interfaces)
    if info.commands.get("ip"):
        for title, args in (
            ("Addresses", ["ip", "-brief", "address", "show"]),
            ("Routes", ["ip", "route", "show"]),
        ):
            result = run_command(args, timeout=4)
            output[title] = result.stdout.strip() if result.returncode == 0 else (result.error or result.stderr.strip() or "Unavailable")
    else:
        output["Addresses"] = "The `ip` utility is not installed."
        output["Routes"] = "The `ip` utility is not installed."
    try:
        resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
        nameservers = [line.split()[1] for line in resolv.splitlines() if line.strip().startswith("nameserver ") and len(line.split()) > 1]
        output["DNS"] = ", ".join(nameservers) if nameservers else "No nameserver listed in /etc/resolv.conf."
    except OSError:
        output["DNS"] = "Could not read /etc/resolv.conf (Android may manage DNS elsewhere)."
    output["Gateway"] = _gateway()
    output["Firewall"] = firewall_status(info)
    return output


def _gateway() -> str:
    result = run_command(["ip", "route", "show", "default"], timeout=3)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            match = re.search(r"\bdefault\s+via\s+(\S+)", line)
            if match and valid_ip(match.group(1)):
                return match.group(1)
    return "Not detected"


def firewall_status(info: PlatformInfo) -> str:
    if info.commands.get("ufw"):
        result = run_command(["ufw", "status"], timeout=3)
        if result.returncode == 0:
            return " ".join(result.stdout.split())[:400]
    if info.commands.get("nft"):
        result = run_command(["nft", "list", "ruleset"], timeout=3, max_output=1500)
        if result.returncode == 0:
            return "nftables ruleset is present (details truncated)."
        return "nft is installed, but ruleset could not be read (permissions may be required)."
    if info.commands.get("iptables"):
        result = run_command(["iptables", "-S"], timeout=3, max_output=1500)
        if result.returncode == 0:
            return "iptables rules are present (details truncated)."
        return "iptables is installed, but rules could not be read (permissions may be required)."
    return "No supported firewall status utility detected."


def ping_gateway(info: PlatformInfo) -> str:
    """Ping the detected default gateway only; caller must obtain explicit confirmation."""
    gateway = _gateway()
    if gateway == "Not detected" or not valid_ip(gateway):
        return "No valid default gateway was detected; ping was not run."
    if not info.commands.get("ping"):
        return "ping utility is not installed; ping was not run."
    command = ["ping", "-c", "4", "-W", "2", gateway]
    result = run_command(command, timeout=12, max_output=5000)
    return result.stdout.strip() or result.error or result.stderr.strip() or f"ping exited with status {result.returncode}."


def validate_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
