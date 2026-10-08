# NetGuard — Linux & Termux Wi-Fi Security Toolkit

NetGuard is a Python 3, standard-library-only, interactive **read-only** Wi-Fi and network diagnostics tool. It is designed for networks you own or are authorized to administer.

## What works

- Linux Wi-Fi list via NetworkManager `nmcli` without requesting a rescan.
- Termux Wi-Fi details via the optional Termux:API companion app and `termux-api` package, subject to Android permissions and OS behavior.
- Local configuration checks, brief security education, and a password-strength heuristic that does not save or display the password.
- Connected-device observations from the existing Linux neighbor/ARP cache only. It does not probe the LAN; the cache may be incomplete.
- Interface, route, DNS, gateway, and best-effort firewall status diagnostics.
- An optional, explicit-confirmation ping to the detected default gateway.
- Text security report saved in the current working directory.

## Deliberate limitations

NetGuard does not crack passwords, capture handshakes, bypass authentication, scan arbitrary hosts, escalate to root, change Wi-Fi settings, or store credentials. Router blocking, pause/resume, bandwidth limits, disconnects, and password changes are **not implemented**: these require vendor- and firmware-specific documented APIs. Use your router's official administration interface. Disconnecting a client cannot erase Wi-Fi credentials already saved on that client's device.

IP and MAC addresses are observations, not proof of a person's identity. A listed device is not necessarily currently online; neighbor-cache state can be stale.

## Linux / Kali installation

Requires Python 3.10+ (no third-party Python packages).

```sh
unzip netguard-linux-termux.zip
cd netguard
python3 -m netguard
```

Optional utilities:

```sh
# Debian/Kali package names; install using your normal system package manager.
sudo apt install network-manager iproute2 iputils-ping
```

`nmcli` provides nearby Wi-Fi details when NetworkManager manages the adapter. The tool does not run `iw scan`; compatible adapters, drivers, permissions, and regulatory constraints vary. Run NetGuard as a normal user; it does not need root for its supported features.

## Termux installation

1. Install Termux from a trusted, current source and update packages:

   ```sh
   pkg update
   pkg install python unzip iproute2
   ```

2. Extract the downloaded archive in Termux and start it:

   ```sh
   unzip netguard-linux-termux.zip
   cd netguard
   python -m netguard
   ```

3. Optional nearby Wi-Fi details:

   ```sh
   pkg install termux-api
   ```

   Also install the matching **Termux:API Android app** from the same trusted distribution source, grant Android's requested Wi-Fi/location permissions, and ensure location services are enabled if your Android version requires them. Android may throttle or return no scan data.

Unrooted Android/Termux generally cannot enable monitor mode, capture arbitrary Wi-Fi traffic, alter low-level Wi-Fi interface settings, or administer the router. NetGuard never attempts root access or bypasses these restrictions. Some Android versions hide MAC addresses or expose only limited neighbor and DNS details.

## Usage and tests

```sh
python -m netguard --help
python -m unittest discover -s tests -v
```

Choose **Generate Security Report** to create `netguard-report-YYYYMMDD-HHMMSS.txt` in the current directory. Reports can contain local IP/MAC/network identifiers; review before sharing.

## Troubleshooting

- **No Wi-Fi list on Linux:** check that NetworkManager is installed and manages the adapter; `nmcli device status` can help diagnose this.
- **No Wi-Fi list on Termux:** verify both the Termux:API package and companion Android app are installed, permissions are granted, and Android permits scan results.
- **No connected devices:** NetGuard reads only the current neighbor/ARP cache. Use your router's own client list for a more complete view; NetGuard does not perform a scan.
- **Firewall says unavailable:** NetGuard reports only what a supported local utility can read; permissions or platform-managed firewalls may prevent inspection.
- **Ping:** runs only after an explicit `y` confirmation and only targets the detected default gateway.
