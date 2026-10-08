from __future__ import annotations

import os
import platform
import shutil
import socket
from dataclasses import dataclass


@dataclass
class PlatformInfo:
    name: str
    termux: bool
    rooted: bool | None
    interfaces: list[str]
    commands: dict[str, bool]


def detect_platform() -> PlatformInfo:
    prefix = os.environ.get("PREFIX", "")
    termux = (
        "ANDROID_ROOT" in os.environ
        or "com.termux" in prefix.lower()
        or os.path.exists("/data/data/com.termux")
    )
    try:
        rooted: bool | None = os.geteuid() == 0
    except AttributeError:
        rooted = None
    try:
        interfaces = [name for _, name in socket.if_nameindex()]
    except OSError:
        interfaces = []
    commands = {
        name: shutil.which(name) is not None
        for name in (
            "ip", "nmcli", "iw", "ping", "termux-wifi-scaninfo",
            "termux-wifi-connectioninfo", "ufw", "nft", "iptables",
        )
    }
    if termux:
        name = "Termux / Android"
    elif platform.system() == "Linux":
        name = "Linux"
    else:
        name = platform.system()
    return PlatformInfo(name, termux, rooted, interfaces, commands)
