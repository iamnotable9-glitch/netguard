from __future__ import annotations

import getpass
import sys
from datetime import datetime
from pathlib import Path

from .devices import connected_devices
from .diagnostics import collect_diagnostics, ping_gateway
from .platform_info import PlatformInfo, detect_platform
from .report import generate_report
from .router import CAPABILITIES, recommendations
from .wifi import EDUCATION, assess_networks, password_feedback, visible_networks


def _clear() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def _pause() -> None:
    try:
        input("\nPress Enter to return to the menu...")
    except (EOFError, KeyboardInterrupt):
        pass


def _table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = min(42, max(widths[i], len(str(value))))
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*(str(v)[:widths[i]] for i, v in enumerate(row))))


def _header(info: PlatformInfo) -> None:
    print("=" * 70)
    print(" NETGUARD | WI-FI SECURITY & NETWORK ADMINISTRATION")
    root = "root" if info.rooted else "not root" if info.rooted is False else "unknown privilege"
    print(f" {info.name} | {root} | read-only / dry-run by design")
    print("=" * 70)


def _wifi_audit(info: PlatformInfo) -> None:
    networks, notes = visible_networks(info)
    if networks:
        _table(
            ["SSID", "BSSID", "Ch/Freq", "Signal", "Security"],
            [[n.ssid, n.bssid, n.channel, n.signal, n.security] for n in networks],
        )
    else:
        print("No nearby Wi-Fi details available.")
    for note in notes:
        print(f"• {note}")
    print("\nVisible configuration checks:")
    for warning in assess_networks(networks):
        print(f"• {warning}")
    print("\nEducation:")
    for title, detail in EDUCATION:
        print(f"• {title}: {detail}")
    print("\nPassword check (local only; input is not saved or displayed):")
    try:
        password = getpass.getpass("Enter a password to assess, or press Enter to skip: ")
        if password:
            for item in password_feedback(password):
                print(f"• {item}")
    except (EOFError, KeyboardInterrupt):
        print("Skipped.")


def _devices() -> None:
    devices, note = connected_devices()
    print(note)
    if not devices:
        print("No cached device entries available.")
        return
    _table(
        ["IP", "MAC (if visible)", "Interface", "Connection state", "Hostname"],
        [[d.ip, d.mac, d.interface, d.status, d.hostname] for d in devices],
    )
    print("These are cached observations. They do not identify a person or guarantee the full client list.")


def _router_controls() -> None:
    print("No router model/API is configured. NetGuard will not guess router commands.")
    for label, text in CAPABILITIES.items():
        print(f"• {label}: {text}")
    print("\nTo change router settings, use the manufacturer's documented administration interface.")


def _diagnostics(info: PlatformInfo) -> None:
    for key, value in collect_diagnostics(info).items():
        print(f"{key}:")
        print(f"  {value or 'No data returned.'}")
    print("\nOptional gateway latency check: sends four ping packets to the detected default gateway.")
    try:
        answer = input("Run this explicitly requested diagnostic? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer == "y":
        print(ping_gateway(info))
    else:
        print("Ping skipped.")


def _report(info: PlatformInfo) -> None:
    report = generate_report(info)
    filename = Path(f"netguard-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt")
    try:
        filename.write_text(report, encoding="utf-8")
        print(f"Report saved: {filename.resolve()}")
        print("The report contains local network identifiers; review it before sharing.")
    except OSError as exc:
        print(f"Could not write report: {exc}")
        print(report)


def _menu(info: PlatformInfo) -> None:
    actions = {
        "1": ("Wi-Fi Security Audit", lambda: _wifi_audit(info)),
        "2": ("Connected Devices", _devices),
        "3": ("Router Administration", _router_controls),
        "4": ("Device Access Control", _router_controls),
        "5": ("Bandwidth Management", _router_controls),
        "6": ("Network Diagnostics", lambda: _diagnostics(info)),
        "7": ("Router Security Recommendations", lambda: [print(f"• {item}") for item in recommendations()]),
        "8": ("Generate Security Report", lambda: _report(info)),
        "9": ("Settings / platform capabilities", lambda: _settings(info)),
    }
    while True:
        _clear()
        _header(info)
        for number, (label, _) in actions.items():
            print(f" {number}. {label}")
        print(" 0. Exit")
        try:
            choice = input("\nSelect an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return
        if choice == "0":
            print("Goodbye.")
            return
        action = actions.get(choice)
        if action:
            _clear()
            _header(info)
            print(f"\n{action[0]}\n")
            try:
                action[1]()
            except (KeyboardInterrupt, BrokenPipeError):
                print("\nOperation cancelled.")
            except Exception as exc:
                print(f"Operation failed safely: {type(exc).__name__}: {exc}")
            _pause()
        else:
            print("Choose one of the listed options.")
            _pause()


def _settings(info: PlatformInfo) -> None:
    print(f"Platform detected: {info.name}")
    print(f"Termux/Android: {'yes' if info.termux else 'no'}")
    print(f"Root privileges: {'yes' if info.rooted else 'no' if info.rooted is False else 'unknown'}")
    print(f"Interfaces: {', '.join(info.interfaces) if info.interfaces else 'none detected'}")
    print("\nUtilities:")
    for name, available in info.commands.items():
        print(f"  {'✓' if available else '—'} {name}")
    if info.termux:
        print("\nAndroid restrictions: unrooted Termux generally cannot enable monitor mode, "
              "capture arbitrary Wi-Fi traffic, or change Wi-Fi interface configuration. "
              "Nearby scan details need Termux:API plus Android permissions.")
    print("\nSafety: no root escalation, password cracking, packet capture, active host scan, "
          "credential storage, or router write operations.")


def main() -> None:
    if "--help" in sys.argv[1:]:
        print("Usage: python -m netguard\n\nInteractive read-only Wi-Fi and network diagnostics for Linux and Termux.")
        return
    info = detect_platform()
    _menu(info)
