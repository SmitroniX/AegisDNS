"""
DNS Resolver & Split-Tunneling Pipeline for AegisDNS.
Supports local blocklist interception, CNAME-cloaking blocking, DNS-over-HTTPS (DoH),
DNS-over-TLS (DoT), UDP/TCP upstream with automatic TC=1 TCP fallback, upstream failover,
split-DNS routing, negative caching, and bounded LRU TTL caching.
"""

from __future__ import annotations
import asyncio
import collections
import socket
import ssl
import struct
import time
import urllib.request
import urllib.error
from typing import Dict, Tuple, Optional, Callable, List, Any
from .dns_packet import DNSPacket, RecordType, RCode
from .blocklist import BlocklistManager


DEFAULT_UPSTREAM_UDP = "94.140.15.15:53"
DEFAULT_UPSTREAM_DOH = "https://dns.adguard-dns.com/dns-query"
DEFAULT_UPSTREAM_DOT = "dns.adguard-dns.com:853"

DNS_PRESETS: Dict[str, dict] = {
    "adguard": {
        "name": "AdGuard DNS (Default Ad-Blocking)",
        "udp": "94.140.15.15:53",
        "doh": "https://dns.adguard-dns.com/dns-query",
        "dot": "dns.adguard-dns.com:853",
        "description": "Blocks ads, telemetry, trackers, and skips JioHotstar episode video ads",
    },
    "adguard-secondary": {
        "name": "AdGuard DNS (Secondary)",
        "udp": "94.140.14.14:53",
        "doh": "https://dns.adguard-dns.com/dns-query",
        "dot": "dns.adguard-dns.com:853",
        "description": "AdGuard secondary ad-blocking resolver",
    },
    "adguard-family": {
        "name": "AdGuard Family Protection",
        "udp": "94.140.14.15:53",
        "doh": "https://family.adguard-dns.com/dns-query",
        "dot": "family.adguard-dns.com:853",
        "description": "Blocks ads, trackers, adult content, and enforces safe search",
    },
    "mullvad-adblock": {
        "name": "Mullvad Ad-Blocking DNS",
        "udp": "194.242.2.3:53",
        "doh": "https://adblock.dns.mullvad.net/dns-query",
        "dot": "adblock.dns.mullvad.net:853",
        "description": "Privacy-focused no-logs resolver blocking ads and trackers",
    },
    "cloudflare": {
        "name": "Cloudflare DNS",
        "udp": "1.1.1.1:53",
        "doh": "https://cloudflare-dns.com/dns-query",
        "dot": "one.one.one.one:853",
        "description": "Fast & private standard DNS resolver",
    },
    "cloudflare-security": {
        "name": "Cloudflare Security (Malware Blocking)",
        "udp": "1.1.1.2:53",
        "doh": "https://security.cloudflare-dns.com/dns-query",
        "dot": "security.cloudflare-dns.com:853",
        "description": "Fast Cloudflare DNS with malware domain filtering",
    },
    "quad9": {
        "name": "Quad9 Secure",
        "udp": "9.9.9.9:53",
        "doh": "https://dns.quad9.net/dns-query",
        "dot": "dns.quad9.net:853",
        "description": "Blocks malware, spyware, and phishing domains",
    },
    "google": {
        "name": "Google Public DNS",
        "udp": "8.8.8.8:53",
        "doh": "https://dns.google/dns-query",
        "dot": "dns.google:853",
        "description": "Google Anycast DNS",
    },
}


STREAMING_SPLIT_DNS_PRESETS: Dict[str, dict] = {
    "hotstar": {
        "name": "Hotstar Ad-Skip Resolver",
        "domains": ["hotstar.com", "hotstar-cdn.com", "hotstar.in", "disneyplus.com"],
        "upstream_udp": "94.140.15.15:53",
        "upstream_doh": "https://dns.adguard-dns.com/dns-query",
        "upstream_dot": "dns.adguard-dns.com:853",
        "description": "Routes JioHotstar domains to AdGuard DNS (94.140.15.15) to skip video ads",
    },
    "netflix": {
        "name": "Netflix Fast Stream Resolver",
        "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"],
        "upstream_udp": "1.1.1.1:53",
        "upstream_doh": "https://cloudflare-dns.com/dns-query",
        "upstream_dot": "one.one.one.one:853",
        "description": "Fast low-latency resolver for Netflix 4K streaming and unblocking",
    },
    "bbc_iplayer": {
        "name": "BBC iPlayer UK SmartDNS",
        "domains": ["bbc.co.uk", "bbci.co.uk", "bbc.com", "bbcmedia.co.uk"],
        "upstream_udp": "212.58.244.70:53",
        "upstream_doh": None,
        "upstream_dot": None,
        "description": "Routes BBC iPlayer domains to UK-localized resolvers for geo-unblocking",
    },
    "prime_video": {
        "name": "Prime Video Unblock Resolver",
        "domains": ["primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net"],
        "upstream_udp": "1.1.1.1:53",
        "upstream_doh": "https://cloudflare-dns.com/dns-query",
        "upstream_dot": "one.one.one.one:853",
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
        upstream_dot: Optional[str] = None,
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
        self.upstream_dot = upstream_dot
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
            "upstream_dot": self.upstream_dot,
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
        upstream_dot: Optional[str] = DEFAULT_UPSTREAM_DOT,
        preset: Optional[str] = None,
        use_doh: bool = False,
        use_dot: bool = False,
        cache_enabled: bool = True,
        max_cache_size: int = 10000,
        negative_cache_ttl: int = 30,
        block_cname_cloaking: bool = True,
        fallback_udp: Optional[str] = None,
        fallback_doh: Optional[str] = None,
        fallback_dot: Optional[str] = None,
        on_query_logged: Optional[Callable[[dict], None]] = None,
    ):
        self.blocklist = blocklist or BlocklistManager()
        if preset and preset in DNS_PRESETS:
            self.upstream_udp = DNS_PRESETS[preset]["udp"]
            self.upstream_doh = DNS_PRESETS[preset]["doh"]
            self.upstream_dot = DNS_PRESETS[preset].get("dot")
        else:
            self.upstream_udp = upstream_udp
            self.upstream_doh = upstream_doh
            self.upstream_dot = upstream_dot
        self.use_doh = use_doh
        self.use_dot = use_dot
        self.cache_enabled = cache_enabled
        self.max_cache_size = max(1, max_cache_size)
        self.negative_cache_ttl = max(0, negative_cache_ttl)
        self.block_cname_cloaking = block_cname_cloaking
        self.fallback_udp = fallback_udp
        self.fallback_doh = fallback_doh
        self.fallback_dot = fallback_dot
        self.cache: "collections.OrderedDict[Tuple[Any, ...], CacheEntry]" = collections.OrderedDict()
        self.split_rules: List[DomainSplitRule] = []
        self.on_query_logged = on_query_logged
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "cname_blocked_queries": 0,
            "cached_queries": 0,
            "upstream_queries": 0,
            "split_queries": 0,
            "tcp_fallbacks": 0,
            "failover_queries": 0,
        }

    def clear_cache(self) -> int:
        cleared = len(self.cache)
        self.cache.clear()
        return cleared

    def set_upstream(
        self,
        preset: Optional[str] = None,
        upstream_udp: Optional[str] = None,
        upstream_doh: Optional[str] = None,
        upstream_dot: Optional[str] = None,
        use_doh: Optional[bool] = None,
        use_dot: Optional[bool] = None,
    ) -> dict:
        """Switches upstream resolver configuration at runtime and flushes cache."""
        if preset:
            if preset not in DNS_PRESETS:
                raise ValueError(f"Unknown DNS preset: '{preset}'")
            p = DNS_PRESETS[preset]
            self.upstream_udp = p["udp"]
            self.upstream_doh = p["doh"]
            self.upstream_dot = p.get("dot")
        if upstream_udp is not None:
            self.upstream_udp = upstream_udp
        if upstream_doh is not None:
            self.upstream_doh = upstream_doh
        if upstream_dot is not None:
            self.upstream_dot = upstream_dot
        if use_doh is not None:
            self.use_doh = use_doh
            if use_doh:
                self.use_dot = False
        if use_dot is not None:
            self.use_dot = use_dot
            if use_dot:
                self.use_doh = False
        self.clear_cache()
        return {
            "upstream_udp": self.upstream_udp,
            "upstream_doh": self.upstream_doh,
            "upstream_dot": self.upstream_dot,
            "use_doh": self.use_doh,
            "use_dot": self.use_dot,
        }

    def add_split_rule(
        self,
        domain_pattern: str,
        upstream_udp: Optional[str] = None,
        upstream_doh: Optional[str] = None,
        upstream_dot: Optional[str] = None,
        preset: Optional[str] = None,
        description: str = "",
    ) -> DomainSplitRule:
        """Adds or updates a domain-based split-DNS routing rule."""
        udp_target = upstream_udp or self.upstream_udp
        doh_target = upstream_doh
        dot_target = upstream_dot
        if preset and preset in DNS_PRESETS:
            udp_target = DNS_PRESETS[preset]["udp"]
            doh_target = DNS_PRESETS[preset]["doh"]
            dot_target = DNS_PRESETS[preset].get("dot")
            if not description:
                description = DNS_PRESETS[preset]["description"]

        # Remove existing rule with same pattern if present
        self.remove_split_rule(domain_pattern)
        rule = DomainSplitRule(
            domain_pattern=domain_pattern,
            upstream_udp=udp_target,
            upstream_doh=doh_target,
            upstream_dot=dot_target,
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
                        upstream_dot=p.get("upstream_dot"),
                        description=p["description"],
                    )
                    count += 1
        return count

    def _cache_put(self, key: Tuple[Any, ...], entry: CacheEntry) -> None:
        self.cache[key] = entry
        self.cache.move_to_end(key)
        while len(self.cache) > self.max_cache_size:
            self.cache.popitem(last=False)

    def _select_transport_tag(
        self, target_udp: str, target_doh: Optional[str], target_dot: Optional[str]
    ) -> Tuple[str, str]:
        if self.use_dot and target_dot:
            return "dot", target_dot
        if self.use_doh and target_doh:
            return "doh", target_doh
        return "udp", target_udp

    async def _dispatch_upstream(
        self,
        query_packet: DNSPacket,
        mode: str,
        target_udp: str,
        target_doh: Optional[str],
        target_dot: Optional[str],
    ) -> DNSPacket:
        if mode == "dot" and target_dot:
            return await self._query_dot(query_packet, target_dot)
        if mode == "doh" and target_doh:
            return await self._query_doh(query_packet, target_doh)
        resp = await self._query_udp(query_packet, target_udp)
        # RFC 7766: Retry over TCP when UDP response is truncated (TC=1)
        if resp and resp.header.tc == 1:
            self.stats["tcp_fallbacks"] += 1
            return await self._query_tcp(query_packet, target_udp)
        return resp

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
            target_dot = split_rule.upstream_dot
            mode, active_target = self._select_transport_tag(target_udp, target_doh, target_dot)
            upstream_tag = f"SPLIT_DNS:{active_target}"
            is_split = True
        else:
            target_udp = self.upstream_udp
            target_doh = self.upstream_doh
            target_dot = self.upstream_dot
            mode, active_target = self._select_transport_tag(target_udp, target_doh, target_dot)
            upstream_tag = active_target
            is_split = False

        # 3. Check Cache (scoped by transport + target so split-DNS rules never serve stale default entries)
        cache_key_scoped = (qname, qtype, f"{mode}:{active_target}")
        cache_key_legacy = (qname, qtype)
        entry = None
        hit_key = None
        if self.cache_enabled:
            if cache_key_scoped in self.cache:
                entry = self.cache[cache_key_scoped]
                hit_key = cache_key_scoped
            elif not is_split and cache_key_legacy in self.cache:
                # Backward-compatible read fallback for manually seeded legacy 2-tuple entries
                entry = self.cache[cache_key_legacy]
                hit_key = cache_key_legacy

        if self.cache_enabled and entry is not None:
            if not entry.is_expired():
                self.cache.move_to_end(hit_key)
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
                if hit_key in self.cache:
                    del self.cache[hit_key]

        # 4. Query Upstream (Default or Split Target) with optional failover
        self.stats["upstream_queries"] += 1
        if is_split:
            self.stats["split_queries"] += 1
        resp_packet: Optional[DNSPacket] = None

        try:
            resp_packet = await self._dispatch_upstream(
                query_packet, mode, target_udp, target_doh, target_dot
            )
        except Exception:
            # Attempt failover upstream if configured (and not a split-DNS override)
            if not is_split and (self.fallback_udp or self.fallback_doh or self.fallback_dot):
                fb_mode, fb_target = self._select_transport_tag(
                    self.fallback_udp or target_udp, self.fallback_doh, self.fallback_dot
                )
                try:
                    self.stats["failover_queries"] += 1
                    resp_packet = await self._dispatch_upstream(
                        query_packet,
                        fb_mode,
                        self.fallback_udp or target_udp,
                        self.fallback_doh,
                        self.fallback_dot,
                    )
                    upstream_tag = f"FAILOVER:{fb_target}"
                except Exception:
                    resp_packet = query_packet.create_response(rcode=RCode.SERVFAIL)
            else:
                resp_packet = query_packet.create_response(rcode=RCode.SERVFAIL)

        # 5. CNAME-Cloaking Inspection
        if (
            self.block_cname_cloaking
            and resp_packet
            and resp_packet.header.rcode == RCode.NOERROR
            and resp_packet.answers
        ):
            cnames = [
                ans.rdata_str
                for ans in resp_packet.answers
                if ans.rtype == RecordType.CNAME and ans.rdata_str
            ]
            if cnames:
                cname_blocked, matched_cname, matched_rule, cname_cat = (
                    self.blocklist.check_cname_chain(qname, cnames)
                )
                if cname_blocked:
                    self.stats["blocked_queries"] += 1
                    self.stats["cname_blocked_queries"] += 1
                    blocked_resp = query_packet.create_response(rcode=RCode.NOERROR)
                    blocked_resp.add_blocked_response(
                        name=qname, qtype=qtype, ttl=60, block_ip="0.0.0.0", block_ipv6="::"
                    )
                    latency_ms = (time.time() - start_time) * 1000
                    self._log_query(
                        qname=qname,
                        qtype=qtype,
                        blocked=True,
                        rule=f"CNAME:{matched_cname} ({matched_rule})",
                        category=cname_cat or "cname-cloaking",
                        rcode=RCode.NOERROR,
                        latency_ms=latency_ms,
                        upstream="CNAME_CLOAKING_BLOCK",
                        client_ip=client_ip,
                    )
                    return blocked_resp

        # 6. Cache Response (positive + RFC 2308 negative caching)
        if self.cache_enabled and resp_packet:
            if resp_packet.answers and resp_packet.header.rcode == RCode.NOERROR:
                min_ttl = min((ans.ttl for ans in resp_packet.answers), default=60)
                ttl = max(5, min(min_ttl, 86400))
                self._cache_put(cache_key_scoped, CacheEntry(resp_packet, time.time() + ttl))
            elif (
                self.negative_cache_ttl > 0
                and resp_packet.header.rcode in (RCode.NXDOMAIN, RCode.NOERROR)
                and not resp_packet.answers
            ):
                soa_min = None
                for ns in resp_packet.authorities:
                    if ns.rtype == RecordType.SOA and ns.rdata_str:
                        parts = ns.rdata_str.split()
                        if len(parts) == 7 and parts[6].isdigit():
                            soa_min = int(parts[6])
                            break
                neg_ttl = min(self.negative_cache_ttl, soa_min) if soa_min is not None else self.negative_cache_ttl
                if neg_ttl > 0:
                    self._cache_put(cache_key_scoped, CacheEntry(resp_packet, time.time() + neg_ttl))

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
    def _parse_upstream_addr(addr_str: str, default_port: int = 53) -> Tuple[str, int]:
        addr_str = addr_str.strip()
        if addr_str.startswith("tls://"):
            addr_str = addr_str[6:]
            default_port = 853
        # Bracketed IPv6: [2606:4700:4700::1111]:53 or [2606:4700:4700::1111]
        if addr_str.startswith("["):
            end_bracket = addr_str.find("]")
            if end_bracket != -1:
                host = addr_str[1:end_bracket]
                rest = addr_str[end_bracket + 1 :]
                port = int(rest[1:]) if rest.startswith(":") else default_port
                return host, port
        # Check if entire string is valid IPv6 without brackets
        try:
            socket.inet_pton(socket.AF_INET6, addr_str)
            return addr_str, default_port
        except OSError:
            pass
        # IPv4 or domain with port: 1.1.1.1:53
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            try:
                port = int(parts[1])
                return parts[0], port
            except ValueError:
                return addr_str, default_port
        return addr_str, default_port

    async def _query_udp(self, query: DNSPacket, upstream_addr: str, timeout: float = 3.0) -> DNSPacket:
        host, port = self._parse_upstream_addr(upstream_addr, default_port=53)
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

    async def _query_tcp(self, query: DNSPacket, upstream_addr: str, timeout: float = 3.0) -> DNSPacket:
        """RFC 7766 DNS-over-TCP upstream query."""
        host, port = self._parse_upstream_addr(upstream_addr, default_port=53)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            writer.write(query.to_tcp_bytes())
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            len_prefix = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            msg_len = struct.unpack("!H", len_prefix)[0]
            resp_data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=timeout)
            return DNSPacket.from_bytes(resp_data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _query_dot(
        self, query: DNSPacket, upstream_dot: str, timeout: float = 4.0
    ) -> DNSPacket:
        """RFC 7858 DNS-over-TLS (DoT) upstream query over port 853."""
        host, port = self._parse_upstream_addr(upstream_dot, default_port=853)
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
            timeout=timeout,
        )
        try:
            writer.write(query.to_tcp_bytes())
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            len_prefix = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            msg_len = struct.unpack("!H", len_prefix)[0]
            resp_data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=timeout)
            return DNSPacket.from_bytes(resp_data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _query_doh(self, query: DNSPacket, doh_url: str, timeout: float = 3.0) -> DNSPacket:
        wire_data = query.to_bytes()

        def sync_fetch():
            req = urllib.request.Request(
                doh_url,
                data=wire_data,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "User-Agent": "AegisDNS/0.3.0",
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
