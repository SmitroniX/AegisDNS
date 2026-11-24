"""
Unified AegisDNS Service Orchestrator.
Combines DNS resolving (UDP + TCP), firewall policies, connection tracking,
blocklist filtering, CNAME cloaking protection, and metrics into a unified daemon.
"""

from __future__ import annotations
import asyncio
import collections
import struct
import time
from typing import Optional, Dict, List, Tuple, Set
from .dns_packet import DNSPacket, RecordType, RCode
from .blocklist import BlocklistManager
from .resolver import (
    DNSResolver,
    DEFAULT_UPSTREAM_UDP,
    DEFAULT_UPSTREAM_DOH,
    DEFAULT_UPSTREAM_DOT,
    DNS_PRESETS,
)
from .firewall import FirewallManager, FirewallRule, FirewallAction
from .connection_tracker import ConnectionTracker, ConnectionFlow
from .wireguard import WireGuardConfig
from .proxy import ProxyManager


class AegisService:
    def __init__(
        self,
        upstream_dns: str = DEFAULT_UPSTREAM_UDP,
        upstream_doh: str = DEFAULT_UPSTREAM_DOH,
        upstream_dot: str = DEFAULT_UPSTREAM_DOT,
        preset: Optional[str] = None,
        use_doh: bool = False,
        use_dot: bool = False,
        block_cname_cloaking: bool = True,
        fallback_udp: Optional[str] = "94.140.14.14:53",
        max_cache_size: int = 10000,
        default_firewall_action: str = FirewallAction.ALLOW,
    ):
        self.blocklist = BlocklistManager()
        self.firewall = FirewallManager(default_action=default_firewall_action)
        self.tracker = ConnectionTracker(history_limit=2000)
        self.proxies = ProxyManager()
        self.wireguard_configs: Dict[str, WireGuardConfig] = {}
        self.dns_logs = collections.deque(maxlen=2000)

        # Resolver with callback to record query logs
        self.resolver = DNSResolver(
            blocklist=self.blocklist,
            upstream_udp=upstream_dns,
            upstream_doh=upstream_doh,
            upstream_dot=upstream_dot,
            preset=preset,
            use_doh=use_doh,
            use_dot=use_dot,
            max_cache_size=max_cache_size,
            block_cname_cloaking=block_cname_cloaking,
            fallback_udp=fallback_udp,
            on_query_logged=self._on_query_logged,
        )

        self._dns_transport = None
        self._tcp_dns_server = None
        self._pending_tasks: Set[asyncio.Task] = set()
        self.is_running = False
        self.start_time = time.time()

    def _on_query_logged(self, log_entry: dict):
        self.dns_logs.appendleft(log_entry)

    async def handle_dns_datagram(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        try:
            req_pkt = DNSPacket.from_bytes(data)
            resp_pkt = await self.resolver.resolve(req_pkt, client_ip=addr[0])
            return resp_pkt.to_bytes()
        except Exception:
            err_resp = DNSPacket()
            err_resp.header.id = (data[0] << 8 | data[1]) if len(data) >= 2 else 0
            err_resp.header.qr = 1
            err_resp.header.rcode = RCode.FORMERR
            return err_resp.to_bytes()

    async def start_dns_server(self, host: str = "127.0.0.1", port: int = 5353):
        loop = asyncio.get_running_loop()
        service_ref = self

        class DNSProtocol(asyncio.DatagramProtocol):
            def __init__(self, service: AegisService):
                self.service = service
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                task = asyncio.create_task(self._process_packet(data, addr))
                service_ref._pending_tasks.add(task)
                task.add_done_callback(service_ref._pending_tasks.discard)

            async def _process_packet(self, data, addr):
                resp = await self.service.handle_dns_datagram(data, addr)
                if self.transport and not self.transport.is_closing() and resp:
                    self.transport.sendto(resp, addr)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self), local_addr=(host, port)
        )
        self._dns_transport = transport
        self.is_running = True

    async def start_tcp_dns_server(self, host: str = "127.0.0.1", port: int = 5353):
        """Starts an RFC 7766 TCP DNS listener alongside the UDP server."""
        async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = writer.get_extra_info("peername") or ("127.0.0.1", 0)
            try:
                len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
                msg_len = struct.unpack("!H", len_bytes)[0]
                if msg_len == 0 or msg_len > 65535:
                    return
                query_bytes = await asyncio.wait_for(reader.readexactly(msg_len), timeout=5.0)
                resp_bytes = await self.handle_dns_datagram(query_bytes, (peer[0], peer[1]))
                writer.write(struct.pack("!H", len(resp_bytes)) + resp_bytes)
                await asyncio.wait_for(writer.drain(), timeout=5.0)
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        self._tcp_dns_server = await asyncio.start_server(handle_tcp_client, host, port)

    async def stop_tcp_dns_server(self):
        if self._tcp_dns_server:
            self._tcp_dns_server.close()
            await self._tcp_dns_server.wait_closed()
            self._tcp_dns_server = None

    def stop_dns_server(self):
        if self._dns_transport:
            self._dns_transport.close()
            self._dns_transport = None
        for task in list(self._pending_tasks):
            task.cancel()
        self._pending_tasks.clear()
        self.is_running = False

    def evaluate_and_track_connection(
        self,
        app_id: str,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        domain: Optional[str] = None,
        is_background: bool = False,
    ) -> Tuple[str, Optional[str], ConnectionFlow]:
        action, reason = self.firewall.evaluate(
            app_id=app_id,
            is_background=is_background,
            protocol=protocol,
            dest_ip=dst_ip,
            dest_port=dst_port,
            domain=domain,
        )

        flow = self.tracker.start_flow(
            app_id=app_id,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            domain=domain,
            action=action,
            rule_reason=reason,
        )
        return action, reason, flow

    def get_dns_logs(self, limit: int = 100, search: Optional[str] = None) -> List[dict]:
        res = []
        for entry in self.dns_logs:
            if search and search.lower() not in entry.get("qname", "").lower():
                continue
            res.append(entry)
            if len(res) >= limit:
                break
        return res

    def get_stats(self) -> dict:
        uptime = round(time.time() - self.start_time, 1)
        res_stats = self.resolver.stats
        total_q = res_stats["total_queries"]
        blocked_q = res_stats["blocked_queries"]
        block_pct = round((blocked_q / total_q * 100), 1) if total_q > 0 else 0.0

        top_blocked = collections.defaultdict(int)
        top_allowed = collections.defaultdict(int)
        for log in self.dns_logs:
            qname = log.get("qname", "")
            if log.get("blocked"):
                top_blocked[qname] += 1
            else:
                top_allowed[qname] += 1

        tracker_metrics = self.tracker.get_metrics()

        return {
            "uptime_seconds": uptime,
            "dns": {
                "total_queries": total_q,
                "blocked_queries": blocked_q,
                "cname_blocked_queries": res_stats.get("cname_blocked_queries", 0),
                "cached_queries": res_stats["cached_queries"],
                "cache_size": len(self.resolver.cache),
                "upstream_queries": res_stats["upstream_queries"],
                "split_queries": res_stats.get("split_queries", 0),
                "tcp_fallbacks": res_stats.get("tcp_fallbacks", 0),
                "failover_queries": res_stats.get("failover_queries", 0),
                "split_rules_count": len(self.resolver.split_rules),
                "block_rate_percent": block_pct,
                "rules_loaded": self.blocklist.stats["rules_loaded"],
                "upstream_udp": self.resolver.upstream_udp,
                "upstream_doh": self.resolver.upstream_doh,
                "upstream_dot": self.resolver.upstream_dot,
                "use_doh": self.resolver.use_doh,
                "use_dot": self.resolver.use_dot,
                "top_blocked_domains": sorted(top_blocked.items(), key=lambda x: x[1], reverse=True)[:5],
                "top_allowed_domains": sorted(top_allowed.items(), key=lambda x: x[1], reverse=True)[:5],
            },
            "firewall": {
                "rules_count": len(self.firewall.rules),
                "lockdown_mode": self.firewall.lockdown_mode,
                "isolated_apps": list(self.firewall.isolated_apps),
                "network_type": self.firewall.current_network_type,
            },
            "connections": tracker_metrics,
        }
