# AegisDNS

> **Advanced DNS Resolver, Application Firewall & WireGuard Engine for Android and Linux**

[![AegisDNS App Build & Test Pipeline](https://github.com/SmitroniX/AegisDNS/actions/workflows/app-build.yml/badge.svg)](https://github.com/SmitroniX/AegisDNS/actions/workflows/app-build.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://golang.org)
[![Android SDK 34+](https://img.shields.io/badge/Android-SDK_34%2B-green.svg)](https://developer.android.com)

AegisDNS is a fast, privacy-respecting network engine and personal firewall. It combines a high-performance Android client, an integrated Go network stack (`firestack`), and a standalone Python userspace engine (`aegis-dns`) for granular traffic control, DNS-level ad/tracker blocking, and WireGuard tunneling.

---

## 🌟 Key Features

### 🛡️ DNS Filtering & Wire Protocol
- **RFC 1035 / RFC 3596 Compliant**: Native DNS wire packet parsing, label pointer decompression with recursion guards, and proper response synthesis (`A` -> `0.0.0.0`, `AAAA` -> `::`, `NODATA` for others).
- **Multi-Format Blocklists**: Out-of-the-box support for standard `/etc/hosts` lists, Adblock syntax (`||tracker.com^`, `@@allowlisted.com`), and CIDR IP blocks.
- **Cache Management**: Accurate TTL decay on cached records and upstream cache busting across all standard DNS record types.

### 🧱 Granular Application Firewall
- **Per-App Traffic Rules**: Block internet access on a per-app UID basis.
- **Rule Matching**: Destination CIDR subnet matching, domain filters, background data restrictions, and metered network guards.
- **Global Lockdown**: Instant one-click kill-switch mode to cut all outbound non-loopback connections.

### 🌐 WireGuard & SOCKS5 Routing
- **WireGuard Configuration**: Full INI parser supporting multi-directive addresses, DNS servers, `AllowedIPs`, and bracketed IPv6 endpoints (`[2606:4700::1]:51820`).
- **SOCKS5 Proxying**: Multi-format proxy connections supporting IPv4 (`0x01`), Domain (`0x03`), and raw 16-byte IPv6 (`0x04`) address types.

---

## 📁 Repository Structure

```
AegisDNS/
├── app/                  # Android application source (Kotlin/Java, UI, Room DB)
├── core/                 # Aegis Userspace Engine (Python 3)
│   ├── aegis/            # Core modules (DNS packet, Resolver, Firewall, Proxy, WireGuard)
│   ├── data/             # Default blocklists and sample configs
│   ├── tests/            # Test suite (53 unit & integration tests)
│   └── pyproject.toml    # Python package definition
├── firestack/            # Go networking engine & tun2socks stack
│   ├── intra/            # Tun, DNS, proxy, and WireGuard Go implementations
│   └── Makefile          # Build scripts
├── .github/
│   └── workflows/
│       └── app-build.yml # Multi-stage CI pipeline (Core tests, Go tests, APK build)
├── build.gradle.kts      # Gradle root build configuration
└── settings.gradle.kts   # Gradle settings & subprojects
```

---

## 🚀 Quick Start

### 1. Using the Core Python CLI (`aegis`)

Install the userspace engine in editable mode:
```bash
pip install -e core/
```

Resolve a domain through the upstream DNS:
```bash
aegis resolve google.com
```

Resolve with blocklist filtering:
```bash
aegis resolve doubleclick.net --blocklist core/data/default_blocklist.txt
```

Verify a WireGuard configuration file:
```bash
aegis wireguard-check /path/to/wg0.conf
```

Start the DNS server and management REST API:
```bash
aegis start --dns-port 5353 --api-port 8080
```

---

### 2. Running Unit Tests

Run the full core test suite (53 tests):
```bash
python3 -m unittest discover -s core/tests -p "test_*.py" -v
```

Run Go network stack tests:
```bash
cd firestack && go test -v ./intra/xdns
```

---

### 3. Building the Android App

Prerequisites:
- Android SDK (API 34+)
- JDK 17
- Gradle 8.x

Build the debug APK:
```bash
./gradlew assembleFdroidFullDebug
```

The compiled APK will be located at:
```
app/build/outputs/apk/fdroidFull/debug/app-fdroid-full-debug.apk
```

---

## 🤖 Continuous Integration

The repository includes a comprehensive GitHub Actions workflow ([`.github/workflows/app-build.yml`](.github/workflows/app-build.yml)):
1. **Core Verification**: Installs `core/` and verifies all 53 unit tests pass on Python 3.11.
2. **Go Engine Verification**: Tests DNS cache busting and packet wiring in `firestack`.
3. **Android Build**: Compiles `assembleFdroidFullDebug` on Ubuntu runners and uploads the APK as a downloadable GitHub Action artifact.

---

## 📜 License & Acknowledgments

- Upstream code derived and inspired by [celzero/rethink-app](https://github.com/celzero/rethink-app).
- Core licensed under Apache-2.0 / GPLv3. See [LICENSE](LICENSE) for details.
