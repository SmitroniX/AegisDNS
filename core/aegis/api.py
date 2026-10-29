"""
REST Management API for AegisDNS / RethinkCore.
Lightweight asynchronous HTTP server providing real-time status, rules, logs, and stats.
"""

from __future__ import annotations
import asyncio
import json
import urllib.parse
from typing import Optional
from .service import AegisService
from .dns_packet import DNSPacket, DNSQuestion, RecordType
from .firewall import FirewallRule


class AegisApiServer:
    def __init__(self, service: AegisService, host: str = "127.0.0.1", port: int = 8053):
        self.service = service
        self.host = host
        self.port = port
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split()
            if len(parts) < 2:
                writer.close()
                await writer.wait_closed()
                return

            method, raw_path = parts[0].upper(), parts[1]
            parsed_url = urllib.parse.urlparse(raw_path)
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)

            # Read headers
            headers = {}
            content_length = 0
            while True:
                h_line = await reader.readline()
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                decoded_h = h_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded_h:
                    k, v = decoded_h.split(":", 1)
                    k_lower = k.strip().lower()
                    headers[k_lower] = v.strip()
                    if k_lower == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            content_length = 0

            # Read body if present
            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)

            # Route request
            status_code, resp_data = await self._route(method, path, query_params, body)

            # Send HTTP response
            body_bytes = json.dumps(resp_data, indent=2).encode("utf-8")
            resp_header = (
                f"HTTP/1.1 {status_code} OK\r\n"
                f"Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")

            writer.write(resp_header + body_bytes)
            await writer.drain()
        except Exception as e:
            err_body = json.dumps({"error": str(e)}).encode("utf-8")
            resp_err = (
                f"HTTP/1.1 500 Internal Server Error\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(err_body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + err_body
            writer.write(resp_err)
            try:
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _route(self, method: str, path: str, query: dict, body: bytes):
        if method == "GET" and path == "/health":
            return 200, {"status": "healthy", "service": "AegisDNS", "version": "1.0.0"}

        elif method == "GET" and path == "/stats":
            return 200, self.service.get_stats()

        elif method == "GET" and path == "/logs/dns":
            limit = int(query.get("limit", [100])[0])
            search = query.get("search", [None])[0]
            logs = self.service.get_dns_logs(limit=limit, search=search)
            return 200, {"count": len(logs), "logs": logs}

        elif method == "GET" and path == "/logs/connections":
            limit = int(query.get("limit", [100])[0])
            app_id = query.get("app_id", [None])[0]
            conns = self.service.tracker.get_history(limit=limit, app_id=app_id)
            return 200, {"count": len(conns), "connections": conns}

        elif method == "GET" and path == "/rules/firewall":
            rules = self.service.firewall.list_rules()
            return 200, {"count": len(rules), "rules": rules}

        elif method == "POST" and path == "/rules/firewall":
            data = json.loads(body.decode("utf-8")) if body else {}
            rule = FirewallRule(
                rule_id=data.get("rule_id", f"rule_{len(self.service.firewall.rules) + 1}"),
                action=data.get("action", "BLOCK"),
                app_id=data.get("app_id"),
                network_type=data.get("network_type", "ANY"),
                block_background=data.get("block_background", False),
                protocol=data.get("protocol"),
                dest_cidr=data.get("dest_cidr"),
                dest_port=data.get("dest_port"),
                domain=data.get("domain"),
                description=data.get("description", ""),
            )
            self.service.firewall.add_rule(rule)
            return 201, {"status": "created", "rule_id": rule.rule_id}

        elif method == "DELETE" and path.startswith("/rules/firewall/"):
            rule_id = path[len("/rules/firewall/") :]
            ok = self.service.firewall.remove_rule(rule_id)
            if ok:
                return 200, {"status": "deleted", "rule_id": rule_id}
            return 404, {"error": "Rule not found", "rule_id": rule_id}

        elif method == "POST" and path == "/rules/lockdown":
            data = json.loads(body.decode("utf-8")) if body else {}
            enabled = bool(data.get("enabled", True))
            self.service.firewall.set_lockdown_mode(enabled)
            return 200, {"status": "ok", "lockdown_mode": enabled}

        elif method == "POST" and path == "/blocklist/reload":
            text = body.decode("utf-8", errors="replace") if body else ""
            category = query.get("category", ["custom"])[0]
            loaded = self.service.blocklist.load_from_text(text, default_category=category)
            return 200, {"status": "reloaded", "rules_loaded": loaded}

        elif method == "POST" and path == "/dns/resolve":
            data = json.loads(body.decode("utf-8")) if body else {}
            domain = data.get("domain", "example.com")
            qtype = int(data.get("qtype", RecordType.A))

            pkt = DNSPacket()
            pkt.header.id = 1234
            pkt.questions.append(DNSQuestion(qname=domain, qtype=qtype))

            resp = await self.service.resolver.resolve(pkt)
            answers = [
                {
                    "name": ans.name,
                    "type": RecordType.to_string(ans.rtype),
                    "ttl": ans.ttl,
                    "data": ans.rdata_str,
                }
                for ans in resp.answers
            ]
            return 200, {
                "domain": domain,
                "rcode": resp.header.rcode,
                "answers": answers,
                "blocked": any(a["data"] == "0.0.0.0" for a in answers),
            }

        return 404, {"error": f"Path '{path}' not found"}
