# AegisDNS / RethinkCore

> **A customized, cross-platform DNS resolver, Ad-Blocker, and Network Firewall engine inspired by and reverse-engineered from [celzero/rethink-app](https://github.com/celzero/rethink-app) using REA MCP.**

---

## Architecture Overview

RethinkDNS consists of two core components:
1. **Android Application & VpnService (`rethink-app`)**:
   - Manages Android `VpnService` TUN interface creation and lifecycle (`BraveVPNService.kt`).
   - Evaluates per-app network permissions and state (`FirewallManager.kt`, `TunFirewallManager.kt`).
   - Tracks DNS query logs, latency, and blocked status (`DnsLogTracker.kt`).
   - Configures WireGuard multi-hop profiles (`WireguardManager.kt`).
2. **Userspace Network Engine (`firestack` Go engine)**:
   - Tun2socks userspace packet interceptor built on `gvisor`.
   - Protocol-level DNS dispatcher supporting UDP 53, DoH, DoT, ODoH, and DNSCrypt.
   - Flow-level connection tracking.

**AegisDNS (`core/aegis`)** is our self-contained, high-performance, cross-platform implementation of this architecture:
- **`dns_packet.py`**: Zero-dependency RFC 1035 wire-format DNS packet encoder and decoder with pointer loop protection, CNAME/PTR/MX/TXT/SOA/OPT/HTTPS compression pointer resolution, and label length validation.
- **`blocklist.py`**: Multi-format blocklist engine supporting hosts file syntax, AdBlock Plus rules (`||domain^`, `||domain^$options`), exception/allowlist rules (`@@||domain^`), exact domain matching, and CIDR IP range blocking.
- **`resolver.py`**: Split-tunneling DNS resolver with local blocklist interception (synthesizes `0.0.0.0` for A, `::` for AAAA, NODATA for other types), in-memory TTL caching with elapsed time decrement (RFC 1035 §7.4), transaction ID verification, and upstream UDP/DoH resolution supporting IPv4 and bracketed IPv6 endpoints.
- **`firewall.py`**: Granular firewall rules engine supporting per-app UID, network conditions (Metered Cellular vs Unmetered Wi-Fi), background data blocking, CIDR IP filters, domain rules, and global lockdown.
- **`connection_tracker.py`**: Real-time 5-tuple flow monitor with bandwidth tracking and circular history buffer.
- **`wireguard.py`**: WireGuard configuration parser supporting multi-line `Address`, `DNS`, and `AllowedIPs` directives, bracketed IPv6 endpoints, Curve25519 32-byte key validator, and INI roundtrip serialization.
- **`proxy.py`**: SOCKS5 client handshake and connect request builder (ATYP 0x01 IPv4, 0x04 IPv6, 0x03 Domain) and HTTP CONNECT proxy router.
- **`service.py` & `api.py`**: Unified daemon orchestrator with Async UDP DNS server and HTTP REST management API.

---

## Quick Start

### 1. Run the Test Suite

```bash
python3 -m unittest discover -s /home/ubuntu/rethink-app/core/tests -p "test_*.py" -v
```
All 53 unit and integration tests execute in ~0.08s.

### 2. CLI Usage (`aegis`)

The CLI is installed system-wide or can be invoked via `python3 -m aegis.cli`:

```bash
# Blocked domain (returns 0.0.0.0 for A, :: for AAAA via blocklist):
aegis resolve doubleclick.net --blocklist /home/ubuntu/rethink-app/core/data/default_blocklist.txt

# Allowed domain (resolved via upstream DNS):
aegis resolve example.com --blocklist /home/ubuntu/rethink-app/core/data/default_blocklist.txt

# Validate a WireGuard profile:
aegis wireguard-check /path/to/profile.conf

# Start daemon with REST API:
aegis start --dns-port 5353 --api-port 8053 --blocklist /home/ubuntu/rethink-app/core/data/default_blocklist.txt
```

### 3. REST API Endpoints

- `GET http://127.0.0.1:8053/health`
- `GET http://127.0.0.1:8053/stats`
- `GET http://127.0.0.1:8053/logs/dns`
- `GET http://127.0.0.1:8053/logs/connections`
- `GET http://127.0.0.1:8053/rules/firewall`
- `POST http://127.0.0.1:8053/rules/firewall`
- `DELETE http://127.0.0.1:8053/rules/firewall/<rule_id>`
- `POST http://127.0.0.1:8053/rules/lockdown`
- `POST http://127.0.0.1:8053/blocklist/reload`
- `POST http://127.0.0.1:8053/dns/resolve`
