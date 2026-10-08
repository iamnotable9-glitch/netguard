from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .safe import run_command, valid_ip, valid_mac


@dataclass
class Device:
    ip: str
    mac: str
    interface: str
    status: str
    hostname: str = "not verified"
    source: str = "kernel neighbor table"


def _parse_ip_neigh(output: str) -> list[Device]:
    devices = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or not valid_ip(parts[0]):
            continue
        mac = next((p for p in parts if valid_mac(p)), "—")
        ifname = "unknown"
        if "dev" in parts and parts.index("dev") + 1 < len(parts):
            ifname = parts[parts.index("dev") + 1]
        state = next((p for p in parts if p in {"REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT"}), "UNKNOWN")
        devices.append(Device(parts[0], mac, ifname, state))
    return devices


def _parse_proc_arp() -> list[Device]:
    path = Path("/proc/net/arp")
    devices: list[Device] = []
    try:
        lines = path.read_text(encoding="ascii", errors="replace").splitlines()[1:]
    except OSError:
        return devices
    for line in lines:
        fields = line.split()
        if len(fields) >= 6 and valid_ip(fields[0]):
            mac = fields[3] if valid_mac(fields[3]) else "—"
            devices.append(Device(fields[0], mac, fields[5], "ARP cached"))
    return devices


def connected_devices() -> tuple[list[Device], str]:
    result = run_command(["ip", "neigh", "show"], timeout=4)
    if result.available and result.returncode == 0:
        return _parse_ip_neigh(result.stdout), (
            "Existing kernel neighbor entries across available interfaces only; "
            "no network probing performed."
        )
    fallback = _parse_proc_arp()
    if fallback:
        return fallback, "Existing ARP cache only; no network probing performed."
    return [], "Neighbor information unavailable (ip utility or readable ARP cache required)."
