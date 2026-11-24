# AegisDNS Core (`aegis-dns`)

> **Zero-dependency Python 3 DNS resolver, CNAME-cloaking Ad-Blocker, Firewall, and WireGuard/WARP engine.**

---

## Architecture Overview

**AegisDNS (`core/aegis`)** provides a self-contained, cross-platform companion engine to the Android client and Go `firestack` stack:
- **`dns_packet.py`**: Zero-dependency RFC 1035 / 3596 / 7766 wire-format DNS packet encoder and decoder with pointer loop & max-255-octet length protection, DNSSEC `AD`/`CD` flag preservation, partial compression pointer normalization for `CNAME`/`NS`/`PTR`/`MX`/`SOA`/`SRV`, `HTTPS`/`SVCB` parsing, and TCP 2-byte framing.
- **`blocklist.py`**: Multi-format blocklist engine supporting `/etc/hosts` syntax, AdBlock DNS rules (`||domain^`, `||domain^$options`), allowlist exceptions (`@@||domain^`), safe skipping of cosmetic/URL-path rules, CIDR IP blocking, duplicate-free accounting, and CNAME-cloaking inspection.
- **`resolver.py`**: Split-DNS resolver with local blocklist + CNAME-cloaking blocking (`0.0.0.0` / `::` / `NODATA`), upstream-scoped bounded LRU cache with RFC 1035 §7.4 TTL decay and RFC 2308 negative caching, UDP/TCP (with automatic `TC=1` TCP fallback), DoH, DoT (RFC 7858), and automatic upstream failover.
- **`firewall.py`**: Granular firewall rules engine supporting per-app rules, metered vs unmetered network conditions, background data blocking, CIDR IP filters, domain rules, loopback-safe app isolation, and global lockdown.
- **`connection_tracker.py`**: Real-time 5-tuple flow monitor with bandwidth tracking and circular history buffer.
- **`wireguard.py`**: Pure-Python RFC 7748 Curve25519 keypair generation, live Cloudflare WARP registration (`POST` + `PATCH warp_enabled: true` + `ClientID`), multi-directive INI parser/serializer, and bracketed IPv6 endpoint validation.
- **`proxy.py`**: SOCKS5 client handshake and connect request builder (`0x01` IPv4, `0x04` IPv6, `0x03` Domain) and per-app / streaming preset routing.
- **`service.py` & `api.py`**: Unified daemon orchestrator with Async UDP + TCP DNS listeners and a hardened HTTP REST management API (proper HTTP status phrases, body cap, timeouts, CORS preflight, optional Bearer token auth).

---

## Quick Start

### 1. Run the Test Suite

```bash
python3 -m unittest discover -s core/tests -p "test_*.py" -v
```
All 98 unit and integration tests execute in ~2s.

### 2. CLI Usage (`aegis`)

```bash
# Install editable package
pip install -e core/

# Resolve with AdGuard DoT or blocklist
aegis resolve example.com --dot --type AAAA
aegis resolve doubleclick.net --blocklist core/data/default_blocklist.txt

# Test blocklist matching
aegis blocklist-test doubleclick.net --blocklist core/data/default_blocklist.txt

# Register a live Cloudflare WARP profile (with ClientID)
aegis register-warp --strict -o warp.conf
aegis wireguard-check warp.conf

# Start UDP + TCP DNS daemon with REST API
aegis start --dns-port 5353 --tcp-dns --dot --api-port 8053 --blocklist core/data/default_blocklist.txt
```

### 3. REST API Endpoints

- `GET /health` (unauthenticated health probe)
- `GET /stats`
- `GET /logs/dns?limit=100&search=...`
- `GET /logs/connections?limit=100&app_id=...`
- `GET /rules/firewall`, `POST /rules/firewall`, `DELETE /rules/firewall/<rule_id>`
- `POST /rules/lockdown`
- `POST /blocklist/reload`, `GET /blocklist/check?domain=...`, `POST /blocklist/domains`, `DELETE /blocklist/domains/<domain>`
- `GET /dns/presets`, `POST /dns/upstream`, `POST /cache/clear`, `POST /dns/resolve`
- `GET /rules/split-dns`, `POST /rules/split-dns`, `DELETE /rules/split-dns/<domain>`, `POST /rules/split-dns/presets`
- `GET /streaming/presets`, `POST /streaming/apply-preset`
- `GET /rules/split-tunnel`, `POST /rules/split-tunnel`, `DELETE /rules/split-tunnel/<app_id>`
- `GET /wireguard/warp-preset`, `POST /wireguard/register-warp`, `POST /wireguard/validate`
- `GET /wireguard/locations`, `GET /wireguard/location-preset?country=JP`
