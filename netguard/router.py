CAPABILITIES = {
    "Device blocking": "Not configured. Requires a documented, vendor-specific router API or admin interface.",
    "Internet pause / restore": "Not configured. Requires a router-supported per-device access-control API.",
    "Bandwidth limits": "Not configured. Requires router support for per-device QoS/rate limits.",
    "Disconnect": "Not configured. Some routers support disconnecting clients; this does not erase saved Wi-Fi credentials on their devices.",
    "Wi-Fi password changes": "Use the router's official administration interface. NetGuard never asks for router credentials.",
}


def recommendations() -> list[str]:
    return [
        "Use WPA3-Personal where supported, otherwise WPA2-Personal with AES/CCMP; disable WEP and TKIP.",
        "Set a long, unique Wi-Fi passphrase and change default router administrator credentials.",
        "Keep router firmware current using the manufacturer's official update process.",
        "Use a guest network for visitors and IoT devices; enable client isolation where appropriate.",
        "Review connected devices in the router's own administration interface; IP/MAC addresses do not identify a person.",
        "Back up router settings before changes. Confirm the router model and documented API before automating controls.",
    ]
