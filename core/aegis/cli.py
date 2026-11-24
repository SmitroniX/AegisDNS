"""
CLI Interface for AegisDNS / RethinkCore.
Allows launching the daemon (UDP/TCP DNS + REST API), querying domains (UDP/DoH/DoT),
testing blocklists, registering live Cloudflare WARP profiles, and validating WireGuard configs.
"""

from __future__ import annotations
import argparse
import asyncio
import os
import sys
from .service import AegisService
from .api import AegisApiServer
from .wireguard import WireGuardConfig
from .dns_packet import DNSPacket, DNSQuestion, RecordType
from .resolver import DNS_PRESETS


def main():
    parser = argparse.ArgumentParser(description="AegisDNS - Advanced DNS Resolver, Firewall & WireGuard Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Start daemon
    p_start = subparsers.add_parser("start", help="Start AegisDNS server and REST API")
    p_start.add_argument("--dns-host", default="127.0.0.1", help="DNS listen host")
    p_start.add_argument("--dns-port", type=int, default=5353, help="DNS listen port")
    p_start.add_argument("--tcp-dns", action="store_true", help="Also start TCP DNS listener on --dns-port")
    p_start.add_argument("--api-host", default="127.0.0.1", help="API listen host")
    p_start.add_argument("--api-port", type=int, default=8053, help="API listen port")
    p_start.add_argument("--api-token", default=None, help="Optional Bearer token protecting Management REST API")
    p_start.add_argument(
        "--preset",
        choices=list(DNS_PRESETS.keys()),
        default="adguard",
        help="DNS upstream preset (default: adguard - ad/tracker blocking)",
    )
    p_start.add_argument("--upstream", default=None, help="Custom upstream DNS (host:port). Overrides preset UDP")
    p_start.add_argument("--doh", action="store_true", help="Use DNS-over-HTTPS (DoH) for upstream queries")
    p_start.add_argument("--dot", action="store_true", help="Use DNS-over-TLS (DoT) for upstream queries")
    p_start.add_argument("--split-streaming", action="store_true", help="Load streaming Split-DNS presets on startup")
    p_start.add_argument("--no-cname-blocking", action="store_true", help="Disable CNAME cloaking protection")
    p_start.add_argument("--blocklist", help="Path to initial blocklist / hosts file")

    # List DNS presets
    subparsers.add_parser("list-presets", help="List built-in DNS upstream presets")

    # Resolve query
    p_resolve = subparsers.add_parser("resolve", help="Resolve a domain name")
    p_resolve.add_argument("domain", help="Domain to resolve")
    p_resolve.add_argument("-t", "--type", default="A", help="DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, HTTPS)")
    p_resolve.add_argument("--preset", choices=list(DNS_PRESETS.keys()), default="adguard", help="DNS upstream preset")
    p_resolve.add_argument("--upstream", default=None, help="Custom upstream DNS (host:port)")
    p_resolve.add_argument("--doh", action="store_true", help="Query via DNS-over-HTTPS (DoH)")
    p_resolve.add_argument("--dot", action="store_true", help="Query via DNS-over-TLS (DoT)")
    p_resolve.add_argument("--blocklist", help="Path to blocklist file")

    # Test blocklist
    p_bl = subparsers.add_parser("blocklist-test", help="Check whether a domain is blocked by a blocklist file")
    p_bl.add_argument("domain", help="Domain to test")
    p_bl.add_argument("--blocklist", required=True, help="Path to blocklist file")

    # Validate WireGuard
    p_wg = subparsers.add_parser("wireguard-check", help="Validate a WireGuard .conf file")
    p_wg.add_argument("file", help="Path to .conf file")

    # Register live Cloudflare WARP
    p_warp = subparsers.add_parser("register-warp", help="Register a live Cloudflare WARP WireGuard profile (with ClientID)")
    p_warp.add_argument("-o", "--output", help="Output file path (prints to stdout if omitted)")
    p_warp.add_argument("--name", default="Cloudflare-WARP", help="Profile name")
    p_warp.add_argument("--locale", default="en_US", help="Locale hint (e.g. en_US, en_GB, en_IN)")
    p_warp.add_argument("--strict", action="store_true", help="Fail with non-zero exit if live registration cannot reach Cloudflare")

    # List VPN Locations
    subparsers.add_parser("list-locations", help="List available Location-Wise VPN presets")

    # Generate Location VPN profile
    p_loc = subparsers.add_parser("create-location-vpn", help="Generate a WireGuard .conf for a country location")
    p_loc.add_argument("country", help="Country code (e.g. US, GB, DE, JP, IN, SG)")
    p_loc.add_argument("--live", action="store_true", help="Register live Cloudflare WARP credentials for this profile")
    p_loc.add_argument("-o", "--output", help="Output file path (prints to stdout if omitted)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "start":
        asyncio.run(_run_server(args))
    elif args.command == "list-presets":
        _run_list_presets()
    elif args.command == "resolve":
        asyncio.run(_run_resolve(args))
    elif args.command == "blocklist-test":
        _run_blocklist_test(args)
    elif args.command == "wireguard-check":
        _run_wg_check(args)
    elif args.command == "register-warp":
        _run_register_warp(args)
    elif args.command == "list-locations":
        _run_list_locations()
    elif args.command == "create-location-vpn":
        _run_create_location_vpn(args)


def _run_list_presets():
    print("\n=== AegisDNS Upstream Presets ===")
    for key, p in DNS_PRESETS.items():
        print(f"\n  • Preset: {key}")
        print(f"    Name:        {p['name']}")
        print(f"    UDP:         {p['udp']}")
        print(f"    DoH:         {p['doh']}")
        print(f"    DoT:         {p.get('dot', 'N/A')}")
        print(f"    Description: {p['description']}")
    print()


async def _run_server(args):
    service = AegisService(
        upstream_dns=args.upstream or DNS_PRESETS[args.preset]["udp"],
        preset=None if args.upstream else args.preset,
        use_doh=args.doh,
        use_dot=args.dot,
        block_cname_cloaking=not args.no_cname_blocking,
    )
    if args.blocklist and os.path.exists(args.blocklist):
        with open(args.blocklist, "r", encoding="utf-8") as f:
            count = service.blocklist.load_from_text(f.read())
            print(f"[*] Loaded {count} rules from {args.blocklist}")
    if args.split_streaming:
        loaded = service.resolver.load_streaming_split_presets()
        print(f"[*] Loaded {loaded} streaming Split-DNS rules")

    transport_mode = "DoT" if args.dot else ("DoH" if args.doh else "UDP")
    print(f"[*] Upstream DNS mode: {transport_mode} (preset={args.preset})")
    print(f"[*] Starting AegisDNS on UDP {args.dns_host}:{args.dns_port}...")
    await service.start_dns_server(host=args.dns_host, port=args.dns_port)

    if args.tcp_dns:
        print(f"[*] Starting AegisDNS TCP listener on {args.dns_host}:{args.dns_port}...")
        await service.start_tcp_dns_server(host=args.dns_host, port=args.dns_port)

    api = AegisApiServer(service, host=args.api_host, port=args.api_port, api_token=args.api_token)
    print(f"[*] Starting Management REST API on http://{args.api_host}:{args.api_port}...")
    await api.start()

    print("[+] AegisDNS running! Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] Stopping AegisDNS...")
        service.stop_dns_server()
        await service.stop_tcp_dns_server()
        await api.stop()
        print("[+] AegisDNS stopped cleanly.")


async def _run_resolve(args):
    try:
        qtype = RecordType.from_string(args.type)
    except ValueError as exc:
        print(f"[-] {exc}")
        sys.exit(1)

    service = AegisService(
        upstream_dns=args.upstream or DNS_PRESETS[args.preset]["udp"],
        preset=None if args.upstream else args.preset,
        use_doh=args.doh,
        use_dot=args.dot,
    )
    if args.blocklist and os.path.exists(args.blocklist):
        with open(args.blocklist, "r", encoding="utf-8") as f:
            service.blocklist.load_from_text(f.read())

    pkt = DNSPacket()
    pkt.questions.append(DNSQuestion(qname=args.domain, qtype=qtype))
    resp = await service.resolver.resolve(pkt)

    print(f"=== Resolution for {args.domain} [{RecordType.to_string(qtype)}] (RCODE: {resp.header.rcode}) ===")
    if not resp.answers:
        print("  (no answer records)")
    for ans in resp.answers:
        print(f"  {ans.name} [{RecordType.to_string(ans.rtype)}] TTL={ans.ttl} -> {ans.rdata_str}")


def _run_blocklist_test(args):
    if not os.path.exists(args.blocklist):
        print(f"[-] Blocklist file not found: {args.blocklist}")
        sys.exit(1)
    service = AegisService()
    with open(args.blocklist, "r", encoding="utf-8") as f:
        loaded = service.blocklist.load_from_text(f.read())
    blocked, rule, category = service.blocklist.is_domain_blocked(args.domain)
    allowed = service.blocklist.is_domain_allowed(args.domain)
    print(f"[*] Loaded {loaded} rules from {args.blocklist}")
    if blocked:
        print(f"[BLOCKED] {args.domain} (rule={rule}, category={category})")
    elif allowed:
        print(f"[ALLOWLISTED] {args.domain}")
    else:
        print(f"[ALLOWED] {args.domain}")


def _run_wg_check(args):
    if not os.path.exists(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)
    with open(args.file, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        cfg = WireGuardConfig.from_ini_string(content)
        ok, errors = cfg.validate()
        if ok:
            print(f"[+] WireGuard configuration '{cfg.name}' is VALID!")
            print(f"    Addresses: {cfg.interface.addresses}")
            if cfg.interface.client_id:
                print(f"    ClientID:  {cfg.interface.client_id}")
            print(f"    Peers: {len(cfg.peers)}")
            for i, p in enumerate(cfg.peers):
                print(f"      Peer {i+1}: Endpoint={p.endpoint}, AllowedIPs={p.allowed_ips}")
        else:
            print(f"[-] Configuration errors ({len(errors)}):")
            for err in errors:
                print(f"    - {err}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Parse error: {e}")
        sys.exit(1)


def _run_register_warp(args):
    try:
        cfg = WireGuardConfig.register_cloudflare_warp(
            name=args.name,
            locale=args.locale,
            allow_fallback=not args.strict,
        )
        ini_text = cfg.to_ini_string()
        status = "LIVE REGISTERED" if cfg.is_registered else "OFFLINE TEMPLATE"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(ini_text + "\n")
            print(f"[+] Wrote Cloudflare WARP profile ({status}) to {args.output}")
        else:
            print(f"\n# Cloudflare WARP Profile ({status})\n")
            print(ini_text)
    except Exception as exc:
        print(f"[-] Error: {exc}")
        sys.exit(1)


def _run_list_locations():
    locations = WireGuardConfig.get_available_locations()
    print(f"\n=== AegisDNS Location-Wise VPN Presets ({len(locations)} available) ===")
    for loc in locations:
        print(f"  {loc['flag']} [{loc['code']}] {loc['name']} - {loc['city']}")
        print(f"     Endpoint: {loc['endpoint']} | DNS: {', '.join(loc['dns'])}")
    print()


def _run_create_location_vpn(args):
    try:
        cfg = WireGuardConfig.create_location_profile(
            args.country,
            register_live=args.live,
            allow_fallback=not args.live,
        )
        ini_text = cfg.to_ini_string()
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(ini_text + "\n")
            print(f"[+] Wrote location WireGuard profile for {args.country.upper()} to {args.output}")
        else:
            print(f"\n# WireGuard Profile: {cfg.name}\n")
            print(ini_text)
    except (ValueError, RuntimeError) as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
