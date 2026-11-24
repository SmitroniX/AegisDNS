"""
REST Management API for AegisDNS / RethinkCore.
Lightweight asynchronous HTTP server providing real-time status, rules, logs, stats,
blocklist management, cache control, runtime upstream switching, and WireGuard tools.
"""

from __future__ import annotations
import asyncio
import hmac
import json
import urllib.parse
from typing import Optional, Dict, Tuple, Any
from .service import AegisService
from .dns_packet import DNSPacket, DNSQuestion, RecordType
from .firewall import FirewallRule
from .proxy import STREAMING_APP_PRESETS
from .resolver import DNS_PRESETS, STREAMING_SPLIT_DNS_PRESETS
from .wireguard import WireGuardConfig


HTTP_REASON_PHRASES: Dict[int, str] = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    413: "Payload Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
}

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB
REQUEST_TIMEOUT_S = 10.0
API_VERSION = "0.3.0"


class AegisApiServer:
    def __init__(
        self,
        service: AegisService,
        host: str = "127.0.0.1",
        port: int = 8053,
        api_token: Optional[str] = None,
        max_body_bytes: int = MAX_BODY_BYTES,
    ):
        self.service = service
        self.host = host
        self.port = port
        self.api_token = api_token
        self.max_body_bytes = max_body_bytes
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @staticmethod
    def _parse_json_body(body: bytes) -> Tuple[Optional[dict], Optional[str]]:
        if not body:
            return {}, None
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, f"Invalid JSON payload: {exc.msg if hasattr(exc, 'msg') else exc}"
        if not isinstance(parsed, dict):
            return None, "JSON payload must be an object"
        return parsed, None

    @staticmethod
    def _parse_int_query(query: dict, key: str, default: int, min_val: int = 1, max_val: int = 10000) -> Tuple[Optional[int], Optional[str]]:
        raw = query.get(key, [str(default)])[0]
        try:
            val = int(raw)
        except (TypeError, ValueError):
            return None, f"Query parameter '{key}' must be an integer"
        return max(min_val, min(val, max_val)), None

    def _is_authorized(self, headers: Dict[str, str], path: str) -> bool:
        if not self.api_token or path == "/health":
            return True
        auth_header = headers.get("authorization", "")
        expected = f"Bearer {self.api_token}"
        return hmac.compare_digest(auth_header, expected)

    async def _send_response(
        self, writer: asyncio.StreamWriter, status_code: int, resp_data: Optional[Any]
    ) -> None:
        reason = HTTP_REASON_PHRASES.get(status_code, "OK")
        if status_code == 204 or resp_data is None:
            resp_header = (
                f"HTTP/1.1 {status_code} {reason}\r\n"
                f"Content-Length: 0\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                f"Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(resp_header)
        else:
            body_bytes = json.dumps(resp_data, indent=2).encode("utf-8")
            resp_header = (
                f"HTTP/1.1 {status_code} {reason}\r\n"
                f"Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                f"Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(resp_header + body_bytes)
        await writer.drain()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=REQUEST_TIMEOUT_S)
            if not line:
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split()
            if len(parts) < 2:
                await self._send_response(writer, 400, {"error": "Malformed HTTP request line"})
                return

            method, raw_path = parts[0].upper(), parts[1]
            parsed_url = urllib.parse.urlparse(raw_path)
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)

            # Read headers
            headers: Dict[str, str] = {}
            content_length = 0
            header_count = 0
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=REQUEST_TIMEOUT_S)
                if not h_line or h_line in (b"\r\n", b"\n"):
                    break
                header_count += 1
                if header_count > 100:
                    await self._send_response(writer, 400, {"error": "Too many HTTP headers"})
                    return
                decoded_h = h_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded_h:
                    k, v = decoded_h.split(":", 1)
                    k_lower = k.strip().lower()
                    headers[k_lower] = v.strip()
                    if k_lower == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            await self._send_response(writer, 400, {"error": "Invalid Content-Length header"})
                            return

            if content_length < 0:
                await self._send_response(writer, 400, {"error": "Negative Content-Length header"})
                return
            if content_length > self.max_body_bytes:
                await self._send_response(
                    writer,
                    413,
                    {"error": f"Request body exceeds maximum size ({self.max_body_bytes} bytes)"},
                )
                return

            # Handle CORS preflight without auth
            if method == "OPTIONS":
                await self._send_response(writer, 204, None)
                return

            # Read body if present
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=REQUEST_TIMEOUT_S
                )

            if not self._is_authorized(headers, path):
                await self._send_response(writer, 401, {"error": "Unauthorized: invalid or missing Bearer token"})
                return

            # Route request
            status_code, resp_data = await self._route(method, path, query_params, body)
            await self._send_response(writer, status_code, resp_data)
        except asyncio.TimeoutError:
            try:
                await self._send_response(writer, 400, {"error": "Request timed out"})
            except Exception:
                pass
        except asyncio.IncompleteReadError:
            try:
                await self._send_response(writer, 400, {"error": "Incomplete request body"})
            except Exception:
                pass
        except Exception as e:
            try:
                await self._send_response(writer, 500, {"error": str(e)})
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
            return 200, {"status": "healthy", "service": "AegisDNS", "version": API_VERSION}

        elif method == "GET" and path == "/stats":
            return 200, self.service.get_stats()

        elif method == "GET" and path == "/logs/dns":
            limit, err = self._parse_int_query(query, "limit", 100)
            if err:
                return 400, {"error": err}
            search = query.get("search", [None])[0]
            logs = self.service.get_dns_logs(limit=limit, search=search)
            return 200, {"count": len(logs), "logs": logs}

        elif method == "GET" and path == "/logs/connections":
            limit, err = self._parse_int_query(query, "limit", 100)
            if err:
                return 400, {"error": err}
            app_id = query.get("app_id", [None])[0]
            conns = self.service.tracker.get_history(limit=limit, app_id=app_id)
            return 200, {"count": len(conns), "connections": conns}

        elif method == "GET" and path == "/rules/firewall":
            rules = self.service.firewall.list_rules()
            return 200, {"count": len(rules), "rules": rules}

        elif method == "POST" and path == "/rules/firewall":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            try:
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
            except ValueError as ve:
                return 400, {"error": str(ve)}
            self.service.firewall.add_rule(rule)
            return 201, {"status": "created", "rule_id": rule.rule_id}

        elif method == "DELETE" and path.startswith("/rules/firewall/"):
            rule_id = urllib.parse.unquote(path[len("/rules/firewall/") :])
            ok = self.service.firewall.remove_rule(rule_id)
            if ok:
                return 200, {"status": "deleted", "rule_id": rule_id}
            return 404, {"error": "Rule not found", "rule_id": rule_id}

        elif method == "POST" and path == "/rules/lockdown":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            enabled = bool(data.get("enabled", True))
            self.service.firewall.set_lockdown_mode(enabled)
            return 200, {"status": "ok", "lockdown_mode": enabled}

        # --- Blocklist Management Endpoints ---
        elif method == "POST" and path == "/blocklist/reload":
            text = body.decode("utf-8", errors="replace") if body else ""
            category = query.get("category", ["custom"])[0]
            loaded = self.service.blocklist.load_from_text(text, default_category=category)
            self.service.resolver.clear_cache()
            return 200, {"status": "reloaded", "rules_loaded": loaded}

        elif method == "GET" and path == "/blocklist/check":
            domain = query.get("domain", [""])[0].strip()
            if not domain:
                return 400, {"error": "Missing 'domain' query parameter"}
            blocked, rule, category = self.service.blocklist.is_domain_blocked(domain)
            allowed = self.service.blocklist.is_domain_allowed(domain)
            return 200, {
                "domain": domain,
                "blocked": blocked,
                "allowed": allowed,
                "matched_rule": rule,
                "category": category,
            }

        elif method == "POST" and path == "/blocklist/domains":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            domain = (data.get("domain") or "").strip()
            if not domain:
                return 400, {"error": "Missing 'domain' in request payload"}
            mode = (data.get("mode") or "block").lower()
            wildcard = bool(data.get("wildcard", False))
            category = data.get("category", "custom")
            if mode == "allow":
                added = self.service.blocklist.add_allowed_domain(domain, wildcard=wildcard)
            elif mode == "block":
                added = self.service.blocklist.add_blocked_domain(domain, wildcard=wildcard, category=category)
            else:
                return 400, {"error": f"Invalid mode '{mode}', expected 'block' or 'allow'"}
            self.service.resolver.clear_cache()
            return 201, {"status": "added" if added else "exists", "domain": domain, "mode": mode}

        elif method == "DELETE" and path.startswith("/blocklist/domains/"):
            domain = urllib.parse.unquote(path[len("/blocklist/domains/") :])
            removed_block = self.service.blocklist.remove_blocked_domain(domain)
            removed_allow = self.service.blocklist.remove_allowed_domain(domain)
            if removed_block or removed_allow:
                self.service.resolver.clear_cache()
                return 200, {"status": "deleted", "domain": domain}
            return 404, {"error": "Domain rule not found", "domain": domain}

        # --- DNS Resolution, Cache & Upstream Control ---
        elif method == "GET" and path == "/dns/presets":
            return 200, {
                "presets": DNS_PRESETS,
                "active": {
                    "upstream_udp": self.service.resolver.upstream_udp,
                    "upstream_doh": self.service.resolver.upstream_doh,
                    "upstream_dot": self.service.resolver.upstream_dot,
                    "use_doh": self.service.resolver.use_doh,
                    "use_dot": self.service.resolver.use_dot,
                },
            }

        elif method == "POST" and path == "/dns/upstream":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            try:
                active = self.service.resolver.set_upstream(
                    preset=data.get("preset"),
                    upstream_udp=data.get("upstream_udp"),
                    upstream_doh=data.get("upstream_doh"),
                    upstream_dot=data.get("upstream_dot"),
                    use_doh=data.get("use_doh"),
                    use_dot=data.get("use_dot"),
                )
                return 200, {"status": "updated", "active": active}
            except ValueError as ve:
                return 400, {"error": str(ve)}

        elif method == "POST" and path == "/cache/clear":
            cleared = self.service.resolver.clear_cache()
            return 200, {"status": "cleared", "entries_removed": cleared}

        elif method == "POST" and path == "/dns/resolve":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            domain = data.get("domain", "example.com")
            raw_qtype = data.get("qtype", RecordType.A)
            try:
                qtype = RecordType.from_string(raw_qtype) if isinstance(raw_qtype, str) else int(raw_qtype)
            except (TypeError, ValueError) as exc:
                return 400, {"error": f"Invalid qtype: {exc}"}

            pkt = DNSPacket()
            pkt.header.id = 1234
            pkt.questions.append(DNSQuestion(qname=domain, qtype=qtype))

            prev_blocked = self.service.resolver.stats["blocked_queries"]
            resp = await self.service.resolver.resolve(pkt)
            was_blocked = self.service.resolver.stats["blocked_queries"] > prev_blocked

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
                "qtype": RecordType.to_string(qtype),
                "rcode": resp.header.rcode,
                "answers": answers,
                "blocked": was_blocked or any(a["data"] in ("0.0.0.0", "::") for a in answers),
            }

        # --- Domain-Based Split-DNS Routing Endpoints ---
        elif method == "GET" and path == "/rules/split-dns":
            rules = self.service.resolver.list_split_rules()
            return 200, {"count": len(rules), "rules": rules}

        elif method == "POST" and path == "/rules/split-dns":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            domain = data.get("domain")
            if not domain:
                return 400, {"error": "Missing 'domain' in request payload"}
            rule = self.service.resolver.add_split_rule(
                domain_pattern=domain,
                upstream_udp=data.get("upstream_udp"),
                upstream_doh=data.get("upstream_doh"),
                upstream_dot=data.get("upstream_dot"),
                preset=data.get("preset"),
                description=data.get("description", ""),
            )
            return 201, {"status": "created", "rule": rule.to_dict()}

        elif method == "DELETE" and path.startswith("/rules/split-dns/"):
            domain = urllib.parse.unquote(path[len("/rules/split-dns/") :])
            ok = self.service.resolver.remove_split_rule(domain)
            if ok:
                return 200, {"status": "deleted", "domain": domain}
            return 404, {"error": "Split DNS rule not found", "domain": domain}

        elif method == "POST" and path == "/rules/split-dns/presets":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            service_names = data.get("services")
            loaded = self.service.resolver.load_streaming_split_presets(service_names)
            return 200, {"status": "loaded", "presets_loaded": loaded}

        # --- Streaming Geo-Unblocking & Per-App Split-Tunneling Endpoints ---
        elif method == "GET" and path == "/streaming/presets":
            return 200, {
                "streaming_app_presets": STREAMING_APP_PRESETS,
                "streaming_split_dns_presets": STREAMING_SPLIT_DNS_PRESETS,
                "current_app_proxies": self.service.proxies.list_app_proxies(),
            }

        elif method == "POST" and path == "/streaming/apply-preset":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            service = data.get("service")
            proxy_name = data.get("proxy_name")
            if not service or not proxy_name:
                return 400, {"error": "Missing 'service' or 'proxy_name'"}
            try:
                packages = self.service.proxies.apply_streaming_preset(service, proxy_name)
                if service in STREAMING_SPLIT_DNS_PRESETS:
                    self.service.resolver.load_streaming_split_presets([service])
                return 200, {
                    "status": "applied",
                    "service": service,
                    "proxy_name": proxy_name,
                    "configured_packages": packages,
                }
            except ValueError as e:
                return 400, {"error": str(e)}

        elif method == "GET" and path == "/rules/split-tunnel":
            return 200, {"app_proxies": self.service.proxies.list_app_proxies()}

        elif method == "POST" and path == "/rules/split-tunnel":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            app_id = data.get("app_id")
            proxy_name = data.get("proxy_name")
            if not app_id or not proxy_name:
                return 400, {"error": "Missing 'app_id' or 'proxy_name'"}
            self.service.proxies.set_app_proxy(app_id, proxy_name)
            return 201, {"status": "created", "app_id": app_id, "proxy_name": proxy_name}

        elif method == "DELETE" and path.startswith("/rules/split-tunnel/"):
            app_id = urllib.parse.unquote(path[len("/rules/split-tunnel/") :])
            ok = self.service.proxies.remove_app_proxy(app_id)
            if ok:
                return 200, {"status": "deleted", "app_id": app_id}
            return 404, {"error": "App proxy rule not found", "app_id": app_id}

        # --- WireGuard Endpoints ---
        elif method == "GET" and path == "/wireguard/warp-preset":
            warp_cfg = WireGuardConfig.create_cloudflare_warp_config()
            return 200, {
                "name": warp_cfg.name,
                "ini_config": warp_cfg.to_ini_string(),
                "addresses": warp_cfg.interface.addresses,
                "endpoint": warp_cfg.peers[0].endpoint if warp_cfg.peers else None,
            }

        elif method == "POST" and path == "/wireguard/register-warp":
            data, err = self._parse_json_body(body)
            if err:
                return 400, {"error": err}
            name = data.get("name", "Cloudflare-WARP")
            locale = data.get("locale", "en_US")
            allow_fallback = bool(data.get("allow_fallback", False))
            try:
                cfg = await asyncio.to_thread(
                    WireGuardConfig.register_cloudflare_warp,
                    name=name,
                    locale=locale,
                    allow_fallback=allow_fallback,
                )
                return 200, {
                    "name": cfg.name,
                    "registered": cfg.is_registered,
                    "client_id": cfg.interface.client_id,
                    "addresses": cfg.interface.addresses,
                    "endpoint": cfg.peers[0].endpoint if cfg.peers else None,
                    "ini_config": cfg.to_ini_string(),
                }
            except RuntimeError as exc:
                return 502, {"error": str(exc)}

        elif method == "POST" and path == "/wireguard/validate":
            ini_text = body.decode("utf-8", errors="replace") if body else ""
            if ini_text.lstrip().startswith("{"):
                data, err = self._parse_json_body(body)
                if err:
                    return 400, {"error": err}
                ini_text = data.get("ini_config", "")
            try:
                cfg = WireGuardConfig.from_ini_string(ini_text)
                valid, errors = cfg.validate()
                return 200, {
                    "valid": valid,
                    "errors": errors,
                    "interface": cfg.interface.to_dict(),
                    "peers": [p.to_dict() for p in cfg.peers],
                }
            except ValueError as ve:
                return 400, {"valid": False, "errors": [str(ve)]}

        elif method == "GET" and path == "/wireguard/locations":
            locations = WireGuardConfig.get_available_locations()
            return 200, {"count": len(locations), "locations": locations}

        elif method == "GET" and path == "/wireguard/location-preset":
            cc = query.get("country", query.get("cc", ["US"]))[0]
            try:
                cfg = WireGuardConfig.create_location_profile(cc)
                return 200, {
                    "name": cfg.name,
                    "country": cc.upper(),
                    "ini_config": cfg.to_ini_string(),
                    "addresses": cfg.interface.addresses,
                    "endpoint": cfg.peers[0].endpoint if cfg.peers else None,
                }
            except ValueError as e:
                return 400, {"error": str(e)}

        return 404, {"error": f"Path '{path}' not found"}
