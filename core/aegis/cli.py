"""
CLI Interface for AegisDNS / RethinkCore.
Allows launching the daemon, querying domains, managing firewall rules, and validating WireGuard profiles.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys
from .service import AegisService
from .api import AegisApiServer
from .wireguard import WireGuardConfig
from .dns_packet import DNSPacket, DNSQuestion, RecordType
from .resolver import DNS_PRESETS, DEFAULT_UPSTREAM_UDP


def main():
    parser = argparse.ArgumentParser(description="AegisDNS - Advanced DNS Resolver & Firewall Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Start daemon
    p_start = subparsers.add_parser("start", help="Start AegisDNS server and REST API")
    p_start.add_argument("--dns-host", default="127.0.0.1", help="DNS listen host")
    p_start.add_argument("--dns-port", type=int, default=5353, help="DNS listen port")
    p_start.add_argument("--api-host", default="127.0.0.1", help="API listen host")
    p_start.add_argument("--api-port", type=int, default=8053, help="API listen port")
    p_start.add_argument("--preset", choices=list(DNS_PRESETS.keys()), default="adguard", help="DNS upstream preset (default: adguard - ad/tracker blocking)")
    p_start.add_argument("--upstream", default=None, help=f"Custom upstream DNS (host:port). Defaults to selected preset")
    p_start.add_argument("--blocklist", help="Path to initial blocklist / hosts file")

    # List DNS presets
    p_presets = subparsers.add_parser("list-presets", help="List built-in DNS upstream presets")

    # Resolve query
    p_resolve = subparsers.add_parser("resolve", help="Resolve a domain name")
    p_resolve.add_argument("domain", help="Domain to resolve")
    p_resolve.add_argument("--blocklist", help="Path to blocklist file")

    # Validate WireGuard
    p_wg = subparsers.add_parser("wireguard-check", help="Validate a WireGuard .conf file")
    p_wg.add_argument("file", help="Path to .conf file")

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
    elif args.command == "wireguard-check":
        _run_wg_check(args)


def _run_list_presets():
    print("\n=== AegisDNS Upstream Presets ===")
    for key, p in DNS_PRESETS.items():
        print(f"\n  • Preset: {key}")
        print(f"    Name:        {p['name']}")
        print(f"    UDP:         {p['udp']}")
        print(f"    DoH:         {p['doh']}")
        print(f"    Description: {p['description']}")
    print()


async def _run_server(args):
    if args.upstream:
        service = AegisService(upstream_dns=args.upstream)
    else:
        service = AegisService(preset=args.preset)
    if args.blocklist and os.path.exists(args.blocklist):
        with open(args.blocklist, "r") as f:
            count = service.blocklist.load_from_text(f.read())
            print(f"[*] Loaded {count} rules from {args.blocklist}")

    print(f"[*] Starting AegisDNS on UDP {args.dns_host}:{args.dns_port}...")
    await service.start_dns_server(host=args.dns_host, port=args.dns_port)

    api = AegisApiServer(service, host=args.api_host, port=args.api_port)
    print(f"[*] Starting Management REST API on http://{args.api_host}:{args.api_port}...")
    await api.start()

    print("[+] AegisDNS running! Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] Stopping AegisDNS...")
        service.stop_dns_server()
        await api.stop()
        print("[+] AegisDNS stopped cleanly.")


async def _run_resolve(args):
    service = AegisService()
    if args.blocklist and os.path.exists(args.blocklist):
        with open(args.blocklist, "r") as f:
            service.blocklist.load_from_text(f.read())

    pkt = DNSPacket()
    pkt.questions.append(DNSQuestion(qname=args.domain, qtype=RecordType.A))
    resp = await service.resolver.resolve(pkt)

    print(f"=== Resolution for {args.domain} (RCODE: {resp.header.rcode}) ===")
    for ans in resp.answers:
        print(f"  {ans.name} [{RecordType.to_string(ans.rtype)}] TTL={ans.ttl} -> {ans.rdata_str}")


def _run_wg_check(args):
    if not os.path.exists(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)
    with open(args.file, "r") as f:
        content = f.read()
    try:
        cfg = WireGuardConfig.from_ini_string(content)
        ok, errors = cfg.validate()
        if ok:
            print(f"[+] WireGuard configuration '{cfg.name}' is VALID!")
            print(f"    Addresses: {cfg.interface.addresses}")
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


if __name__ == "__main__":
    main()
