"""
DNS Resolver & Split-Tunneling Pipeline for AegisDNS.
Supports local blocklist interception, DNS-over-HTTPS (DoH), standard UDP upstream,
and in-memory TTL caching.
"""

from __future__ import annotations
import asyncio
import socket
import time
import urllib.request
import urllib.error
from typing import Dict, Tuple, Optional, Callable, List
from .dns_packet import DNSPacket, RecordType, RCode
from .blocklist import BlocklistManager


DEFAULT_UPSTREAM_UDP = "94.140.15.15:53"
DEFAULT_UPSTREAM_DOH = "https://dns.adguard-dns.com/dns-query"

DNS_PRESETS: Dict[str, dict] = {
    "adguard": {
        "name": "AdGuard DNS (Default Ad-Blocking)",
        "udp": "94.140.15.15:53",
        "doh": "https://dns.adguard-dns.com/dns-query",
        "description": "Blocks ads, telemetry, trackers, and skips JioHotstar episode video ads",
    },
    "adguard-secondary": {
        "name": "AdGuard DNS (Secondary)",
        "udp": "94.140.14.14:53",
        "doh": "https://dns.adguard-dns.com/dns-query",
        "description": "AdGuard secondary ad-blocking resolver",
    },
    "cloudflare": {
        "name": "Cloudflare DNS",
        "udp": "1.1.1.1:53",
        "doh": "https://cloudflare-dns.com/dns-query",
        "description": "Fast & private standard DNS resolver",
    },
    "quad9": {
        "name": "Quad9 Secure",
        "udp": "9.9.9.9:53",
        "doh": "https://dns.quad9.net/dns-query",
        "description": "Blocks malware, spyware, and phishing domains",
    },
    "google": {
        "name": "Google Public DNS",
        "udp": "8.8.8.8:53",
        "doh": "https://dns.google/dns-query",
        "description": "Google Anycast DNS",
    },
}



STREAMING_SPLIT_DNS_PRESETS: Dict[str, dict] = {
    "hotstar": {
        "name": "Hotstar Ad-Skip Resolver",
        "domains": ["hotstar.com", "hotstar-cdn.com", "hotstar.in", "disneyplus.com"],
        "upstream_udp": "94.140.15.15:53",
        "upstream_doh": "https://dns.adguard-dns.com/dns-query",
        "description": "Routes JioHotstar domains to AdGuard DNS (94.140.15.15) to skip video ads",
    },
    "netflix": {
        "name": "Netflix Fast Stream Resolver",
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
        "upstream_udp": "1.1.1.1:53",
        "upstream_doh": "https://cloudflare-dns.com/dns-query",
        "description": "Fast low-latency resolver for Netflix 4K streaming and unblocking",
    },
    "bbc_iplayer": {
        "name": "BBC iPlayer UK SmartDNS",
        "domains": ["bbc.co.uk", "bbci.co.uk", "bbc.com", "bbcmedia.co.uk"],
        "upstream_udp": "212.58.244.70:53",
        "upstream_doh": None,
        "description": "Routes BBC iPlayer domains to UK-localized resolvers for geo-unblocking",
    },
    "prime_video": {
        "name": "Prime Video Unblock Resolver",
        "domains": ["primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net"],
        "upstream_udp": "1.1.1.1:53",
        "upstream_doh": "https://cloudflare-dns.com/dns-query",
        "description": "Optimized SmartDNS routing for Amazon Prime Video",
    },
}


class DomainSplitRule:
    """Represents a domain-to-upstream DNS routing rule (supports exact match & wildcards)."""

    def __init__(
        self,
        domain_pattern: str,
        upstream_udp: str = DEFAULT_UPSTREAM_UDP,
        upstream_doh: Optional[str] = None,
        description: str = "",
        is_wildcard: bool = False,
    ):
        raw = domain_pattern.strip().lower().rstrip(".")
        if raw.startswith("*."):
            self.pattern = raw[2:]
            self.is_wildcard = True
        else:
            self.pattern = raw
            self.is_wildcard = is_wildcard
        self.upstream_udp = upstream_udp
        self.upstream_doh = upstream_doh
        self.description = description

    def matches(self, domain: str) -> bool:
        norm = domain.strip().lower().rstrip(".")
        if self.is_wildcard:
            return norm == self.pattern or norm.endswith("." + self.pattern)
        return norm == self.pattern

    def to_dict(self) -> dict:
        return {
            "domain": ("*." + self.pattern) if self.is_wildcard else self.pattern,
            "upstream_udp": self.upstream_udp,
            "upstream_doh": self.upstream_doh,
            "description": self.description,
            "is_wildcard": self.is_wildcard,
        }


class CacheEntry:
    def __init__(self, packet: DNSPacket, expires_at: float):
        self.packet = packet
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class DNSResolver:
    def __init__(
        self,
        blocklist: Optional[BlocklistManager] = None,
        upstream_udp: str = DEFAULT_UPSTREAM_UDP,
        upstream_doh: Optional[str] = DEFAULT_UPSTREAM_DOH,
        preset: Optional[str] = None,
        use_doh: bool = False,
        cache_enabled: bool = True,
        on_query_logged: Optional[Callable[[dict], None]] = None,
    ):
        self.blocklist = blocklist or BlocklistManager()
        if preset and preset in DNS_PRESETS:
            self.upstream_udp = DNS_PRESETS[preset]["udp"]
            self.upstream_doh = DNS_PRESETS[preset]["doh"]
        else:
            self.upstream_udp = upstream_udp
            self.upstream_doh = upstream_doh
        self.use_doh = use_doh
        self.cache_enabled = cache_enabled
        self.cache: Dict[Tuple[str, int, str], CacheEntry] = {}
        self.split_rules: List[DomainSplitRule] = []
        self.on_query_logged = on_query_logged
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "cached_queries": 0,
            "upstream_queries": 0,
            "split_queries": 0,
        }

    def add_split_rule(
        self,
        domain_pattern: str,
        upstream_udp: Optional[str] = None,
        upstream_doh: Optional[str] = None,
        preset: Optional[str] = None,
        description: str = "",
    ) -> DomainSplitRule:
        """Adds or updates a domain-based split-DNS routing rule."""
        udp_target = upstream_udp or self.upstream_udp
        doh_target = upstream_doh
        if preset and preset in DNS_PRESETS:
            udp_target = DNS_PRESETS[preset]["udp"]
            doh_target = DNS_PRESETS[preset]["doh"]
            if not description:
                description = DNS_PRESETS[preset]["description"]

        # Remove existing rule with same pattern if present
        self.remove_split_rule(domain_pattern)
        rule = DomainSplitRule(
            domain_pattern=domain_pattern,
            upstream_udp=udp_target,
            upstream_doh=doh_target,
            description=description,
        )
        self.split_rules.append(rule)
        return rule

    def remove_split_rule(self, domain_pattern: str) -> bool:
        norm = domain_pattern.strip().lower().rstrip(".")
        if norm.startswith("*."):
            norm = norm[2:]
        initial_len = len(self.split_rules)
        self.split_rules = [r for r in self.split_rules if r.pattern != norm]
        return len(self.split_rules) < initial_len

    def get_split_rule(self, domain: str) -> Optional[DomainSplitRule]:
        for r in self.split_rules:
            if r.matches(domain):
                return r
        return None

    def list_split_rules(self) -> List[dict]:
        return [r.to_dict() for r in self.split_rules]

    def load_streaming_split_presets(self, service_names: Optional[List[str]] = None) -> int:
        """Loads default domain-based split-DNS presets for streaming/unblocking services."""
        count = 0
        names = service_names or list(STREAMING_SPLIT_DNS_PRESETS.keys())
        for sname in names:
            if sname in STREAMING_SPLIT_DNS_PRESETS:
                p = STREAMING_SPLIT_DNS_PRESETS[sname]
                for d in p["domains"]:
                    self.add_split_rule(
                        domain_pattern="*." + d,
                        upstream_udp=p["upstream_udp"],
                        upstream_doh=p["upstream_doh"],
                        description=p["description"],
                    )
                    count += 1
        return count

    async def resolve(self, query_packet: DNSPacket, client_ip: str = "127.0.0.1") -> DNSPacket:
        start_time = time.time()
        self.stats["total_queries"] += 1

        if not query_packet.questions:
            return query_packet.create_response(rcode=RCode.FORMERR)

        q = query_packet.questions[0]
        qname = q.clean_name()
        qtype = q.qtype

        # 1. Blocklist Inspection
        is_blocked, rule, category = self.blocklist.is_domain_blocked(qname)
        if is_blocked:
            self.stats["blocked_queries"] += 1
            resp = query_packet.create_response(rcode=RCode.NOERROR)
            resp.add_blocked_response(name=qname, qtype=qtype, ttl=60, block_ip="0.0.0.0", block_ipv6="::")

            latency_ms = (time.time() - start_time) * 1000
            self._log_query(
                qname=qname,
                qtype=qtype,
                blocked=True,
                rule=rule,
                category=category,
                rcode=RCode.NOERROR,
                latency_ms=latency_ms,
                upstream="LOCAL_BLOCKLIST",
                client_ip=client_ip,
            )
            return resp

        # 2. Check Domain-Based Split-DNS Routing
        split_rule = self.get_split_rule(qname)
        if split_rule:
            target_udp = split_rule.upstream_udp
            target_doh = split_rule.upstream_doh
            upstream_tag = f"SPLIT_DNS:{target_doh if self.use_doh and target_doh else target_udp}"
            is_split = True
        else:
            target_udp = self.upstream_udp
            target_doh = self.upstream_doh
            upstream_tag = self.upstream_doh if self.use_doh and self.upstream_doh else self.upstream_udp
            is_split = False

        # 3. Check Cache
        cache_key_2 = (qname, qtype)
        cache_key_3 = (qname, qtype, target_udp)
        entry = None
        hit_key = None
        if self.cache_enabled:
            if cache_key_3 in self.cache:
                entry = self.cache[cache_key_3]
                hit_key = cache_key_3
            elif cache_key_2 in self.cache:
                entry = self.cache[cache_key_2]
                hit_key = cache_key_2

        if self.cache_enabled and entry is not None:
            if not entry.is_expired():
                self.stats["cached_queries"] += 1
                cached_resp = DNSPacket.from_bytes(entry.packet.to_bytes())
                cached_resp.header.id = query_packet.header.id
                # Decrement TTL on all answers to reflect elapsed time (RFC 1035 §7.4)
                remaining_ttl = max(1, int(entry.expires_at - time.time()))
                for ans in cached_resp.answers:
                    ans.ttl = min(ans.ttl, remaining_ttl)
                for ns in cached_resp.authorities:
                    ns.ttl = min(ns.ttl, remaining_ttl)
                for ar in cached_resp.additionals:
                    ar.ttl = min(ar.ttl, remaining_ttl)

                latency_ms = (time.time() - start_time) * 1000
                self._log_query(
                    qname=qname,
                    qtype=qtype,
                    blocked=False,
                    rule=None,
                    category=None,
                    rcode=cached_resp.header.rcode,
                    latency_ms=latency_ms,
                    upstream="CACHE",
                    client_ip=client_ip,
                )
                return cached_resp
            else:
                if hit_key:
                    del self.cache[hit_key]

        # 4. Query Upstream (Default or Split Target)
        self.stats["upstream_queries"] += 1
        if is_split:
            self.stats["split_queries"] += 1
        resp_packet: Optional[DNSPacket] = None

        try:
            if self.use_doh and target_doh:
                resp_packet = await self._query_doh(query_packet, target_doh)
            else:
                resp_packet = await self._query_udp(query_packet, target_udp)
        except Exception:
            # Fallback or error
            resp_packet = query_packet.create_response(rcode=RCode.SERVFAIL)

        # 5. Cache Response
        if self.cache_enabled and resp_packet and resp_packet.answers:
            min_ttl = min((ans.ttl for ans in resp_packet.answers), default=60)
            ttl = max(5, min(min_ttl, 86400))
            self.cache[cache_key_2] = CacheEntry(resp_packet, time.time() + ttl)

        latency_ms = (time.time() - start_time) * 1000
        self._log_query(
            qname=qname,
            qtype=qtype,
            blocked=False,
            rule=None,
            category=None,
            rcode=resp_packet.header.rcode if resp_packet else RCode.SERVFAIL,
            latency_ms=latency_ms,
            upstream=upstream_tag,
            client_ip=client_ip,
        )
        return resp_packet

    @staticmethod
    def _parse_upstream_addr(addr_str: str) -> Tuple[str, int]:
        addr_str = addr_str.strip()
        # Bracketed IPv6: [2606:4700:4700::1111]:53 or [2606:4700:4700::1111]
        if addr_str.startswith("["):
            end_bracket = addr_str.find("]")
            if end_bracket != -1:
                host = addr_str[1:end_bracket]
                rest = addr_str[end_bracket + 1 :]
                port = int(rest[1:]) if rest.startswith(":") else 53
                return host, port
        # Check if entire string is valid IPv6 without brackets
        try:
            socket.inet_pton(socket.AF_INET6, addr_str)
            return addr_str, 53
        except OSError:
            pass
        # IPv4 with port or domain: 1.1.1.1:53
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            try:
                port = int(parts[1])
                return parts[0], port
            except ValueError:
                return addr_str, 53
        return addr_str, 53

    async def _query_udp(self, query: DNSPacket, upstream_addr: str, timeout: float = 3.0) -> DNSPacket:
        host, port = self._parse_upstream_addr(upstream_addr)
        wire_data = query.to_bytes()

        loop = asyncio.get_running_loop()
        future = loop.create_future()

        class UDPClientProtocol(asyncio.DatagramProtocol):
            def __init__(self, target_future):
                self.target_future = target_future
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport
                transport.sendto(wire_data)

            def datagram_received(self, data, addr):
                if len(data) >= 2:
                    resp_id = (data[0] << 8) | data[1]
                    if resp_id != query.header.id:
                        return  # Ignore unsolicited / mismatched response
                if not self.target_future.done():
                    self.target_future.set_result(data)
                if self.transport:
                    self.transport.close()

            def error_received(self, exc):
                if not self.target_future.done():
                    self.target_future.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPClientProtocol(future), remote_addr=(host, port)
        )
        try:
            resp_data = await asyncio.wait_for(future, timeout=timeout)
            return DNSPacket.from_bytes(resp_data)
        finally:
            transport.close()

    async def _query_doh(self, query: DNSPacket, doh_url: str, timeout: float = 3.0) -> DNSPacket:
        wire_data = query.to_bytes()

        def sync_fetch():
            req = urllib.request.Request(
                doh_url,
                data=wire_data,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "User-Agent": "AegisDNS/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read()

        loop = asyncio.get_running_loop()
        raw_resp = await loop.run_in_executor(None, sync_fetch)
        return DNSPacket.from_bytes(raw_resp)

    def _log_query(self, **kwargs):
        if self.on_query_logged:
            kwargs["timestamp"] = time.time()
            self.on_query_logged(kwargs)
