from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .platform_info import PlatformInfo
from .safe import run_command


@dataclass
class Network:
    ssid: str
    bssid: str = "—"
    channel: str = "—"
    signal: str = "—"
    security: str = "Unknown"
    source: str = "system utility"


def _split_nmcli_row(row: str) -> list[str]:
    """Split nmcli's escaped colon-separated terse output."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in row:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _security_label(value: str) -> str:
    if not value or value.strip().upper() in {"", "--", "OPEN"}:
        return "Open / unsecured"
    return value.strip()


def visible_networks(info: PlatformInfo) -> tuple[list[Network], list[str]]:
    notes: list[str] = []
    if info.termux:
        result = run_command(["termux-wifi-scaninfo"], timeout=8)
        if result.available and result.returncode == 0:
            try:
                rows = json.loads(result.stdout)
                networks = []
                for row in rows if isinstance(rows, list) else []:
                    if not isinstance(row, dict):
                        continue
                    networks.append(Network(
                        ssid=str(row.get("ssid") or "(hidden SSID)"),
                        bssid=str(row.get("bssid") or "—"),
                        channel=str(row.get("frequency_mhz") or row.get("frequency") or "—"),
                        signal=(f"{row.get('rssi')} dBm" if row.get("rssi") is not None else "—"),
                        security=_security_label(str(row.get("capabilities") or "Unknown")),
                        source="Termux:API cached Wi-Fi scan",
                    ))
                if networks:
                    return networks, notes
                notes.append("Termux:API returned no Wi-Fi scan results.")
            except (json.JSONDecodeError, TypeError):
                notes.append("Could not parse Termux:API scan results.")
        else:
            notes.append(
                "Nearby Wi-Fi details require the Termux:API app and the "
                "termux-api package, Android location/Wi-Fi permissions, and a recent OS scan."
            )
        connection = run_command(["termux-wifi-connectioninfo"], timeout=5)
        if connection.available and connection.returncode == 0:
            try:
                row = json.loads(connection.stdout)
                if isinstance(row, dict) and row.get("ssid"):
                    notes.append(f"Current connection: {row.get('ssid')} (connection details only).")
            except json.JSONDecodeError:
                pass
        return [], notes

    result = run_command([
        "nmcli", "--terse", "--escape", "yes", "--fields",
        "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "no",
    ])
    if result.available and result.returncode == 0:
        networks: list[Network] = []
        for line in result.stdout.splitlines():
            fields = _split_nmcli_row(line)
            if len(fields) < 5:
                continue
            networks.append(Network(
                ssid=fields[0] or "(hidden SSID)",
                bssid=fields[1] or "—",
                channel=fields[2] or "—",
                signal=f"{fields[3]}%" if fields[3] else "—",
                security=_security_label(fields[4]),
                source="NetworkManager (no rescan requested)",
            ))
        return networks, notes
    if result.available and result.returncode != 0:
        notes.append(result.stderr.strip() or "NetworkManager did not return Wi-Fi results.")
    else:
        notes.append("NetworkManager (nmcli) is not installed; nearby Wi-Fi listing is unavailable.")

    # Do not run `iw scan`: scanning may require elevated privileges and can disrupt an adapter.
    link = run_command(["iw", "dev"], timeout=3)
    if link.available and link.returncode == 0 and re.search(r"\bInterface\s+\S+", link.stdout):
        notes.append("An iw-capable adapter is present; active scan is intentionally not run.")
    return [], notes


def assess_networks(networks: list[Network]) -> list[str]:
    warnings = []
    for network in networks:
        security = network.security.lower()
        if security in {"open / unsecured", "unknown"} or "wep" in security:
            warnings.append(
                f"{network.ssid}: visible security is {network.security}; use WPA2-AES or WPA3."
            )
        elif "wpa" not in security:
            warnings.append(f"{network.ssid}: security could not be confidently classified.")
    if not networks:
        warnings.append("No nearby network security details were available to assess.")
    return warnings


def password_feedback(password: str) -> list[str]:
    """Return heuristic guidance only; the password is never retained or printed."""
    findings = []
    if len(password) < 12:
        findings.append("Use at least 12 characters; 16 or more is a better target.")
    else:
        findings.append("Length is a good start; a long, unique passphrase is preferable.")
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    if classes <= 2:
        findings.append("Consider a few unrelated words or a wider mix of character types.")
    if re.search(r"(.)\1{3,}", password) or password.lower() in {"password123", "123456789012"}:
        findings.append("Avoid repeated characters and common or predictable patterns.")
    findings.append("This is a local heuristic, not a password crackability test; never reuse passwords.")
    return findings


EDUCATION = [
    ("WPA2", "A widely supported Wi-Fi security standard. Prefer WPA2-Personal with AES/CCMP; avoid legacy TKIP."),
    ("WPA3", "A newer standard with stronger password-based authentication; use it when all devices support it."),
    ("WEP", "Obsolete and insecure. Replace it with WPA2-AES or WPA3."),
    ("Encryption", "Protects wireless traffic over the air. It does not replace updates, unique passwords, or endpoint security."),
    ("Authentication", "Verifies a user/device can join the network. A strong, unique Wi-Fi passphrase matters."),
    ("Handshake", "A protocol exchange used to establish protected Wi-Fi sessions. NetGuard does not capture or crack handshakes."),
]
