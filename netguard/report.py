from __future__ import annotations

from datetime import datetime

from .devices import connected_devices
from .diagnostics import collect_diagnostics
from .platform_info import PlatformInfo
from .router import recommendations
from .wifi import assess_networks, visible_networks


def generate_report(info: PlatformInfo) -> str:
    networks, notes = visible_networks(info)
    devices, device_note = connected_devices()
    diagnostics = collect_diagnostics(info)
    lines = [
        "NETGUARD — NETWORK SECURITY REPORT",
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Platform: {info.name}",
        "Scope: local, read-only observations; no intrusive scans or router changes.",
        "",
        "VISIBLE WI-FI NETWORKS",
    ]
    if networks:
        lines.extend(
            f"- {n.ssid} | BSSID: {n.bssid} | channel/frequency: {n.channel} | signal: {n.signal} | security: {n.security}"
            for n in networks
        )
    else:
        lines.append("- No network details returned by available system utilities.")
    lines += ["", "AUDIT NOTES", *[f"- {item}" for item in (notes + assess_networks(networks))]]
    lines += ["", "OBSERVED NEIGHBOR DEVICES", f"- {device_note}"]
    if devices:
        lines.extend(f"- IP {d.ip} | MAC {d.mac} | interface {d.interface} | state {d.status}; hostname not verified" for d in devices)
    else:
        lines.append("- No cached neighbor records available.")
    lines += ["", "LOCAL DIAGNOSTICS"]
    lines.extend(f"- {key}: {value}" for key, value in diagnostics.items())
    lines += ["", "RECOMMENDATIONS", *[f"- {item}" for item in recommendations()]]
    lines += [
        "",
        "Limitations: Wi-Fi scan results depend on OS permissions, adapter, and installed utilities. "
        "Neighbor entries are cached observations, not a complete inventory. No router controls are configured.",
    ]
    return "\n".join(lines) + "\n"
