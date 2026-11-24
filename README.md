# AegisDNS

> **Advanced DNS Resolver, Application Firewall & WireGuard Engine for Android and Linux**

[![AegisDNS App Build & Test Pipeline](https://github.com/SmitroniX/AegisDNS/actions/workflows/app-build.yml/badge.svg)](https://github.com/SmitroniX/AegisDNS/actions/workflows/app-build.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://golang.org)
[![Android SDK 34+](https://img.shields.io/badge/Android-SDK_34%2B-green.svg)](https://developer.android.com)

AegisDNS is a fast, privacy-respecting network engine and personal firewall. It combines a customized Android client (defaulting to AdGuard DoH ad-blocking), an integrated Go network stack (`firestack`), and a zero-dependency Python userspace engine (`aegis-dns`) for granular traffic control, DNS-level ad/tracker & CNAME-cloaking blocking, Split-DNS routing, and WireGuard/WARP tunneling.

---

## 🌟 Key Features

### 🛡️ DNS Filtering & Wire Protocol
- **RFC 1035 / 3596 / 7766 / 7858 Compliant**: Native DNS wire packet parsing with recursion & max-255-octet length guards, DNSSEC `AD`/`CD` flag preservation, partial compression pointer normalization, and proper blocked response synthesis (`A` → `0.0.0.0`, `AAAA` → `::`, `NODATA` for non-IP types).
- **Encrypted & Resilient Transports**: UDP, TCP (with automatic `TC=1` truncation fallback), DNS-over-HTTPS (**DoH**), DNS-over-TLS (**DoT**), and automatic upstream failover.
- **CNAME-Cloaking Protection**: Inspects upstream CNAME chains against the blocklist to defeat first-party CNAME tracker cloaking (while respecting explicit allowlists).
- **Multi-Format Blocklists**: Out-of-the-box support for `/etc/hosts` lists, Adblock DNS syntax (`||tracker.com^`, `@@||allowlisted.com^`), cosmetic/URL-rule filtering, and CIDR IP blocks.
- **Bounded LRU & Split-DNS Cache**: Upstream-scoped TTL-decaying LRU cache with RFC 2308 negative caching and zero cross-upstream cache poisoning.

### 🧱 Granular Application Firewall
- **Per-App Traffic Rules**: Block internet access on a per-app UID basis.
- **Rule Matching**: Destination CIDR subnet matching, domain filters, background data restrictions, metered network guards, and loopback-safe app isolation.
- **Global Lockdown**: Instant one-click kill-switch mode to cut all outbound non-loopback connections.

### 🌐 WireGuard, Cloudflare WARP & SOCKS5 Routing
- **Live Cloudflare WARP + `ClientID`**: Pure-Python RFC 7748 Curve25519 key generation and Android OkHttp registration with `PATCH warp_enabled: true` activation and 3-byte `ClientID` reserved header injection for `firestack`.
- **One-Click & Location-Wise VPN Presets**: Atomic One-WireGuard activation with proper Android `VpnService.prepare()` consent handling across 12 country presets (`US`, `GB`, `DE`, `JP`, `SG`, `CA`, `NL`, `IN`, `FR`, `AU`, `CH`, `BR`).
- **WireGuard Configuration**: Full INI parser supporting multi-directive addresses, DNS servers, `ClientID`, `AllowedIPs`, and bracketed IPv6 endpoints (`[2606:4700::1]:51820`).
- **SOCKS5 Proxying**: Multi-format proxy connections supporting IPv4 (`0x01`), Domain (`0x03`), and raw 16-byte IPv6 (`0x04`) address types.

---

## 📁 Repository Structure

```
AegisDNS/
├── app/                  # Android application source (Kotlin/Java, UI, Room DB)
├── core/                 # Aegis Userspace Engine (Python 3, zero external deps)
│   ├── aegis/            # Core modules (DNS packet, Resolver, Firewall, Proxy, WireGuard, API, CLI)
│   ├── data/             # Default blocklists
│   ├── tests/            # Test suite (98 unit & integration tests)
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

Resolve a domain via AdGuard DoT or DoH:
```bash
aegis resolve google.com --dot --type AAAA
aegis resolve doubleclick.net --blocklist core/data/default_blocklist.txt
```

Test a domain against a blocklist:
```bash
aegis blocklist-test doubleclick.net --blocklist core/data/default_blocklist.txt
```

Register a live Cloudflare WARP profile (with `ClientID` + `warp_enabled`):
```bash
aegis register-warp --strict -o warp.conf
aegis wireguard-check warp.conf
```

List and generate location-wise VPN presets:
```bash
aegis list-locations
aegis create-location-vpn JP --live -o wg-jp.conf
```

Start the UDP + TCP DNS server and authenticated management REST API:
```bash
aegis start --dns-port 5353 --tcp-dns --dot --split-streaming --api-port 8053 --api-token "your-secret"
```

---

### 2. Running Unit Tests

Run the full core test suite (98 tests):
```bash
python3 -m unittest discover -s core/tests -p "test_*.py" -v
```

Run Go network stack tests:
```bash
cd firestack && go test -v ./intra/xdns ./intra/core/wire
```

Run Android unit tests:
```bash
./gradlew testFdroidFullDebugUnitTest
```

---

### 3. Building the Android App

Prerequisites:
- Android SDK (API 34+ / compileSdk 37)
- JDK 17
- Gradle 9.x (via `./gradlew`)

Build the debug APK:
```bash
./gradlew assembleFdroidFullDebug
```

The compiled APKs will be located under:
```
app/build/outputs/apk/fdroidFull/debug/
```

---

## 🤖 Continuous Integration

The repository includes a multi-stage GitHub Actions workflow ([`.github/workflows/app-build.yml`](.github/workflows/app-build.yml)):
1. **Core Verification**: Installs `core/` and verifies all 98 unit tests pass on Python 3.11.
2. **Go Engine Verification**: Tests DNS cache busting and packet wiring in `firestack`.
3. **Android Build**: Compiles `assembleFdroidFullDebug` on Ubuntu runners and uploads the APK as a downloadable GitHub Action artifact (and publishes GitHub Releases on `v*` tags).

---

## 📜 License & Acknowledgments

- Upstream Android & Go engine derived from [celzero/rethink-app](https://github.com/celzero/rethink-app).
- Licensed under Apache-2.0 / GPLv3. See [LICENSE](LICENSE) for details.
