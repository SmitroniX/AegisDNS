import asyncio
import base64
import json
import socket
import struct
import unittest
import urllib.error
import urllib.request
from unittest.mock import AsyncMock, MagicMock, patch

from aegis.api import AegisApiServer
from aegis.blocklist import BlocklistManager
from aegis.dns_packet import (
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRR,
    RCode,
    RecordType,
    decode_dns_name,
    encode_dns_name,
)
from aegis.firewall import FirewallAction, FirewallManager, FirewallRule
from aegis.resolver import DNSResolver
from aegis.service import AegisService
from aegis.wireguard import (
    WireGuardConfig,
    WireGuardInterface,
    WireGuardPeer,
    _x25519_scalar_mult,
    derive_public_key,
    generate_keypair,
    is_valid_client_id,
)


class TestDNSPacketFixesAndUpgrades(unittest.TestCase):
    def test_header_dnssec_ad_cd_flags_roundtrip(self):
        hdr = DNSHeader(id=0xABCD, qr=1, rd=1, ra=1, ad=1, cd=1, rcode=RCode.NOERROR)
        raw = hdr.to_bytes()
        parsed, _ = DNSHeader.from_bytes(raw, 0)
        self.assertEqual(parsed.ad, 1)
        self.assertEqual(parsed.cd, 1)

    def test_partial_compression_pointer_in_cname_reserializes_cleanly(self):
        # Question at offset 12: "app.example.com." (offset 16 = "example.com.")
        hdr = DNSHeader(id=0x1111, qr=1, qdcount=1, ancount=1).to_bytes()
        q = encode_dns_name("app.example.com") + struct.pack("!HH", RecordType.CNAME, 1)
        # Answer: name=ptr(12), rtype=CNAME, rclass=1, ttl=120, rdata = \x03cdn + ptr(16)
        rdata = b"\x03cdn\xc0\x10"
        ans = b"\xc0\x0c" + struct.pack("!HHIH", RecordType.CNAME, 1, 120, len(rdata)) + rdata
        pkt = DNSPacket.from_bytes(hdr + q + ans)
        self.assertEqual(pkt.answers[0].rdata_str, "cdn.example.com")

        # Shift offsets by adding a different question, then re-serialize & parse
        pkt.questions[0] = DNSQuestion("a.b", RecordType.CNAME)
        reparsed = DNSPacket.from_bytes(pkt.to_bytes())
        self.assertEqual(reparsed.answers[0].rdata_str, "cdn.example.com")

    def test_max_255_wire_name_length_enforced(self):
        # 5 labels of 60 chars = 305 wire octets > 255 -> rejected on decode
        too_long = (b"\x3c" + b"a" * 60) * 5 + b"\x00"
        with self.assertRaises(ValueError):
            decode_dns_name(too_long, 0)

    def test_srv_record_and_tcp_framing(self):
        pkt = DNSPacket()
        pkt.header.id = 77
        pkt.questions.append(DNSQuestion("_sip._tcp.example.com", RecordType.SRV))
        pkt.add_srv_record("_sip._tcp.example.com", 10, 60, 5060, "sip1.example.com", ttl=180)
        tcp_bytes = pkt.to_tcp_bytes()
        parsed = DNSPacket.from_tcp_bytes(tcp_bytes)
        self.assertEqual(parsed.header.id, 77)
        self.assertEqual(parsed.answers[0].rdata_str, "10 60 5060 sip1.example.com")

    def test_record_type_from_string(self):
        self.assertEqual(RecordType.from_string("aaaa"), RecordType.AAAA)
        self.assertEqual(RecordType.from_string("HTTPS"), RecordType.HTTPS)
        self.assertEqual(RecordType.from_string("TYPE99"), 99)
        with self.assertRaises(ValueError):
            RecordType.from_string("NOT_A_TYPE")


class TestBlocklistFixesAndUpgrades(unittest.TestCase):
    def test_skips_cosmetic_and_url_path_adblock_rules(self):
        bl = BlocklistManager()
        text = """
        example.com##.ad-banner
        example.com#@#.allowed-banner
        ||cdn.example.com/ads/banner.js^
        ||realtracker.example^
        ||realtracker.example^
        """
        loaded = bl.load_from_text(text)
        self.assertEqual(loaded, 1)
        self.assertEqual(bl.stats["rules_loaded"], 1)
        self.assertTrue(bl.is_domain_blocked("sub.realtracker.example")[0])
        self.assertFalse(bl.is_domain_blocked("example.com")[0])
        self.assertFalse(bl.is_domain_blocked("cdn.example.com")[0])

    def test_remove_blocked_and_allowed_domains(self):
        bl = BlocklistManager()
        bl.add_blocked_domain("ads.test", wildcard=True)
        self.assertTrue(bl.is_domain_blocked("sub.ads.test")[0])
        self.assertTrue(bl.remove_blocked_domain("ads.test"))
        self.assertFalse(bl.is_domain_blocked("sub.ads.test")[0])
        self.assertEqual(bl.stats["rules_loaded"], 0)

    def test_cname_cloaking_detection(self):
        bl = BlocklistManager()
        bl.add_blocked_domain("tracker.thirdparty.net", wildcard=True, category="tracker")
        blocked, cname, rule, cat = bl.check_cname_chain(
            "metrics.myshop.com", ["s1.tracker.thirdparty.net"]
        )
        self.assertTrue(blocked)
        self.assertEqual(cname, "s1.tracker.thirdparty.net")
        self.assertEqual(cat, "tracker")

        # Explicitly allowlisted original domain bypasses CNAME cloaking block
        bl.add_allowed_domain("metrics.myshop.com")
        blocked2, _, _, _ = bl.check_cname_chain("metrics.myshop.com", ["s1.tracker.thirdparty.net"])
        self.assertFalse(blocked2)


class TestWireGuardFixesAndUpgrades(unittest.TestCase):
    def test_rfc7748_x25519_test_vector(self):
        # Official RFC 7748 Section 6.1 Curve25519 test vector
        alice_priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        expected_alice_pub = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        derived = _x25519_scalar_mult(alice_priv)
        self.assertEqual(derived, expected_alice_pub)

        priv_b64 = base64.b64encode(alice_priv).decode("ascii")
        self.assertEqual(
            derive_public_key(priv_b64),
            base64.b64encode(expected_alice_pub).decode("ascii"),
        )

    def test_generate_keypair_public_differs_from_private(self):
        priv, pub = generate_keypair()
        self.assertNotEqual(priv, pub)
        self.assertEqual(derive_public_key(priv), pub)

    def test_client_id_validation_and_ini_roundtrip(self):
        self.assertTrue(is_valid_client_id("r3oC"))  # 3 bytes
        self.assertFalse(is_valid_client_id("not-valid-base64!!!"))
        self.assertFalse(is_valid_client_id("AAAAAA=="))  # 4 bytes, not 3

        priv, _ = generate_keypair()
        _, peer_pub = generate_keypair()
        cfg = WireGuardConfig(
            name="WARP-With-CID",
            interface=WireGuardInterface(
                private_key=priv,
                addresses=["172.16.0.2/32"],
                dns_servers=["1.1.1.1"],
                mtu=1280,
                client_id="r3oC",
            ),
            peers=[WireGuardPeer(public_key=peer_pub, endpoint="162.159.192.2:2408")],
        )
        ok, errors = cfg.validate()
        self.assertTrue(ok, f"Unexpected errors: {errors}")
        ini = cfg.to_ini_string()
        self.assertIn("ClientID = r3oC", ini)

        parsed = WireGuardConfig.from_ini_string(ini)
        self.assertEqual(parsed.interface.client_id, "r3oC")
        self.assertTrue(parsed.validate()[0])

    def test_register_cloudflare_warp_live_mock_sends_public_key_and_patches_and_captures_client_id(self):
        calls = []

        class FakeResp:
            def __init__(self, payload: dict):
                self._data = json.dumps(payload).encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(req, timeout=8.0):
            calls.append((req.get_method(), req.full_url, json.loads(req.data.decode("utf-8")), dict(req.headers)))
            if req.get_method() == "POST":
                return FakeResp(
                    {
                        "id": "reg-12345",
                        "token": "tok-secret",
                        "warp_enabled": False,
                        "config": {
                            "client_id": "r3oC",
                            "interface": {"addresses": {"v4": "172.16.0.99", "v6": "2606:4700:110::99"}},
                            "peers": [
                                {
                                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                                    "endpoint": {
                                        "v4": "162.159.192.2:0",
                                        "host": "engage.cloudflareclient.com:2408",
                                        "ports": [2408, 500],
                                    },
                                }
                            ],
                        },
                    }
                )
            return FakeResp({"id": "reg-12345", "warp_enabled": True})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            cfg = WireGuardConfig.register_cloudflare_warp(name="TestWARP", allow_fallback=False)

        self.assertTrue(cfg.is_registered)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[1][0], "PATCH")
        self.assertTrue(calls[1][1].endswith("/reg/reg-12345"))
        self.assertEqual(calls[1][2], {"warp_enabled": True})

        # Verify sent key is the derived public key, NEVER the raw private key
        sent_key = calls[0][2]["key"]
        self.assertNotEqual(sent_key, cfg.interface.private_key)
        self.assertEqual(sent_key, derive_public_key(cfg.interface.private_key))

        # Verify ClientID, addresses, and resolved IPv4:2408 endpoint
        self.assertEqual(cfg.interface.client_id, "r3oC")
        self.assertIn("172.16.0.99/32", cfg.interface.addresses)
        self.assertEqual(cfg.peers[0].endpoint, "162.159.192.2:2408")

    def test_register_cloudflare_warp_strict_raises_on_network_failure(self):
        with patch("urllib.request.urlopen", side_effect=OSError("offline")):
            with self.assertRaises(RuntimeError):
                WireGuardConfig.register_cloudflare_warp(allow_fallback=False)

    def test_endpoint_empty_host_and_bad_mtu_rejected(self):
        _, pub = generate_keypair()
        p1 = WireGuardPeer(public_key=pub, endpoint=":51820")
        self.assertTrue(any("endpoint" in e.lower() for e in p1.validate()))
        p2 = WireGuardPeer(public_key=pub, endpoint="[]:51820")
        self.assertTrue(any("endpoint" in e.lower() for e in p2.validate()))

        bad_ini = "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nMTU = notanumber\n"
        with self.assertRaises(ValueError):
            WireGuardConfig.from_ini_string(bad_ini)


class TestResolverAndServiceUpgrades(unittest.IsolatedAsyncioTestCase):
    async def test_split_dns_cache_isolation(self):
        resolver = DNSResolver(upstream_udp="1.1.1.1:53", cache_enabled=True)

        resp_default = DNSPacket()
        resp_default.add_a_record("stream.example.com", "1.1.1.10", ttl=300)
        resp_split = DNSPacket()
        resp_split.add_a_record("stream.example.com", "94.140.15.99", ttl=300)

        async def mock_udp(pkt, addr):
            return resp_split if addr.startswith("94.140.") else resp_default

        resolver._query_udp = AsyncMock(side_effect=mock_udp)

        q1 = DNSPacket()
        q1.questions.append(DNSQuestion("stream.example.com", RecordType.A))
        r1 = await resolver.resolve(q1)
        self.assertEqual(r1.answers[0].rdata_str, "1.1.1.10")

        # Now add a split-DNS rule: must NOT return stale cached 1.1.1.10!
        resolver.add_split_rule("stream.example.com", upstream_udp="94.140.15.15:53")
        q2 = DNSPacket()
        q2.questions.append(DNSQuestion("stream.example.com", RecordType.A))
        r2 = await resolver.resolve(q2)
        self.assertEqual(r2.answers[0].rdata_str, "94.140.15.99")

    async def test_lru_cache_eviction_bound(self):
        resolver = DNSResolver(upstream_udp="1.1.1.1:53", max_cache_size=2)

        async def mock_udp(pkt, addr):
            r = pkt.create_response()
            r.add_a_record(pkt.questions[0].clean_name(), "10.0.0.1", ttl=300)
            return r

        resolver._query_udp = AsyncMock(side_effect=mock_udp)
        for d in ("a.test", "b.test", "c.test"):
            q = DNSPacket()
            q.questions.append(DNSQuestion(d, RecordType.A))
            await resolver.resolve(q)
        self.assertEqual(len(resolver.cache), 2)

    async def test_cname_cloaking_blocked_in_resolver(self):
        bl = BlocklistManager()
        bl.add_blocked_domain("cloaked-tracker.net", wildcard=True, category="tracker")
        resolver = DNSResolver(blocklist=bl, upstream_udp="1.1.1.1:53", block_cname_cloaking=True)

        upstream_resp = DNSPacket()
        upstream_resp.header.qr = 1
        upstream_resp.add_cname_record("metrics.firstparty.com", "sub.cloaked-tracker.net", ttl=300)
        upstream_resp.add_a_record("sub.cloaked-tracker.net", "203.0.113.5", ttl=300)
        resolver._query_udp = AsyncMock(return_value=upstream_resp)

        q = DNSPacket()
        q.header.id = 42
        q.questions.append(DNSQuestion("metrics.firstparty.com", RecordType.A))
        resp = await resolver.resolve(q)

        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].rdata_str, "0.0.0.0")
        self.assertEqual(resolver.stats["cname_blocked_queries"], 1)

    async def test_udp_truncation_triggers_tcp_fallback(self):
        resolver = DNSResolver(upstream_udp="1.1.1.1:53")

        truncated = DNSPacket()
        truncated.header.qr = 1
        truncated.header.tc = 1

        full_tcp = DNSPacket()
        full_tcp.header.qr = 1
        full_tcp.add_txt_record("big.example.com", "full-tcp-answer", ttl=120)

        resolver._query_udp = AsyncMock(return_value=truncated)
        resolver._query_tcp = AsyncMock(return_value=full_tcp)

        q = DNSPacket()
        q.questions.append(DNSQuestion("big.example.com", RecordType.TXT))
        resp = await resolver.resolve(q)

        self.assertEqual(resp.answers[0].rdata_str, "full-tcp-answer")
        self.assertEqual(resolver.stats["tcp_fallbacks"], 1)
        resolver._query_tcp.assert_awaited_once()

    async def test_upstream_failover_on_primary_error(self):
        resolver = DNSResolver(upstream_udp="94.140.15.15:53", fallback_udp="1.1.1.1:53")
        fb_resp = DNSPacket()
        fb_resp.header.qr = 1
        fb_resp.add_a_record("ok.example.com", "93.184.216.34", ttl=120)

        async def mock_udp(pkt, addr):
            if addr.startswith("94.140."):
                raise asyncio.TimeoutError("primary down")
            return fb_resp

        resolver._query_udp = AsyncMock(side_effect=mock_udp)
        q = DNSPacket()
        q.questions.append(DNSQuestion("ok.example.com", RecordType.A))
        resp = await resolver.resolve(q)
        self.assertEqual(resp.answers[0].rdata_str, "93.184.216.34")
        self.assertEqual(resolver.stats["failover_queries"], 1)

    async def test_tcp_dns_server_roundtrip(self):
        service = AegisService()
        service.blocklist.add_blocked_domain("ads.tcp.test")
        tcp_port = 15354
        await service.start_tcp_dns_server(host="127.0.0.1", port=tcp_port)
        try:
            q = DNSPacket()
            q.header.id = 0x2222
            q.questions.append(DNSQuestion("ads.tcp.test", RecordType.A))
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
            writer.write(q.to_tcp_bytes())
            await writer.drain()
            len_hdr = await reader.readexactly(2)
            resp_len = struct.unpack("!H", len_hdr)[0]
            raw = await reader.readexactly(resp_len)
            writer.close()
            await writer.wait_closed()

            resp = DNSPacket.from_bytes(raw)
            self.assertEqual(resp.header.id, 0x2222)
            self.assertEqual(resp.answers[0].rdata_str, "0.0.0.0")
        finally:
            await service.stop_tcp_dns_server()


class TestApiHardeningAndNewEndpoints(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.service = AegisService()
        self.service.blocklist.add_blocked_domain("blocked.api.test", wildcard=True)
        self.port = 18059
        self.token = "secret-aegis-token"
        self.api = AegisApiServer(
            self.service, host="127.0.0.1", port=self.port, api_token=self.token, max_body_bytes=4096
        )
        await self.api.start()

    async def asyncTearDown(self):
        await self.api.stop()

    def _req(self, method: str, path: str, body: bytes = b"", auth: bool = True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=body if body else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, resp.reason, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            return e.code, e.reason, (json.loads(raw) if raw else None)

    async def test_auth_and_status_reason_phrases(self):
        # /health is exempt from auth
        code, reason, data = await asyncio.to_thread(self._req, "GET", "/health", b"", False)
        self.assertEqual(code, 200)
        self.assertEqual(reason, "OK")
        self.assertEqual(data["version"], "0.3.0")

        # Protected endpoint without token -> 401 Unauthorized
        code, reason, _ = await asyncio.to_thread(self._req, "GET", "/stats", b"", False)
        self.assertEqual(code, 401)
        self.assertEqual(reason, "Unauthorized")

        # Unknown path -> 404 Not Found (not "404 OK")
        code, reason, _ = await asyncio.to_thread(self._req, "GET", "/does-not-exist")
        self.assertEqual(code, 404)
        self.assertEqual(reason, "Not Found")

    async def test_cors_options_and_body_limits_and_bad_json(self):
        code, reason, _ = await asyncio.to_thread(self._req, "OPTIONS", "/stats", b"", False)
        self.assertEqual(code, 204)
        self.assertEqual(reason, "No Content")

        code, reason, _ = await asyncio.to_thread(self._req, "POST", "/dns/resolve", b"{bad json")
        self.assertEqual(code, 400)
        self.assertEqual(reason, "Bad Request")

        code, reason, _ = await asyncio.to_thread(
            self._req, "POST", "/blocklist/reload", b"x" * 5000
        )
        self.assertEqual(code, 413)
        self.assertEqual(reason, "Payload Too Large")

    async def test_resolve_blocked_aaaa_and_txt_reported_as_blocked(self):
        code, _, data_aaaa = await asyncio.to_thread(
            self._req,
            "POST",
            "/dns/resolve",
            json.dumps({"domain": "blocked.api.test", "qtype": "AAAA"}).encode(),
        )
        self.assertEqual(code, 200)
        self.assertTrue(data_aaaa["blocked"])
        self.assertEqual(data_aaaa["answers"][0]["data"], "::")

        code, _, data_txt = await asyncio.to_thread(
            self._req,
            "POST",
            "/dns/resolve",
            json.dumps({"domain": "blocked.api.test", "qtype": "TXT"}).encode(),
        )
        self.assertEqual(code, 200)
        self.assertTrue(data_txt["blocked"])
        self.assertEqual(data_txt["answers"], [])

    async def test_blocklist_upstream_cache_and_wg_validate_endpoints(self):
        # Add blocklist domain
        code, _, _ = await asyncio.to_thread(
            self._req,
            "POST",
            "/blocklist/domains",
            json.dumps({"domain": "newad.example", "wildcard": True}).encode(),
        )
        self.assertEqual(code, 201)

        # Check blocklist
        code, _, chk = await asyncio.to_thread(self._req, "GET", "/blocklist/check?domain=sub.newad.example")
        self.assertEqual(code, 200)
        self.assertTrue(chk["blocked"])

        # Delete blocklist domain
        code, _, _ = await asyncio.to_thread(self._req, "DELETE", "/blocklist/domains/newad.example")
        self.assertEqual(code, 200)

        # Switch upstream preset + DoT
        code, _, up = await asyncio.to_thread(
            self._req,
            "POST",
            "/dns/upstream",
            json.dumps({"preset": "quad9", "use_dot": True}).encode(),
        )
        self.assertEqual(code, 200)
        self.assertEqual(up["active"]["upstream_dot"], "dns.quad9.net:853")
        self.assertTrue(up["active"]["use_dot"])

        # Clear cache
        code, _, clr = await asyncio.to_thread(self._req, "POST", "/cache/clear", b"{}")
        self.assertEqual(code, 200)
        self.assertEqual(clr["status"], "cleared")

        # Validate WireGuard INI
        cfg = WireGuardConfig.create_cloudflare_warp_config(client_id="r3oC")
        code, _, val = await asyncio.to_thread(
            self._req,
            "POST",
            "/wireguard/validate",
            json.dumps({"ini_config": cfg.to_ini_string()}).encode(),
        )
        self.assertEqual(code, 200)
        self.assertTrue(val["valid"])
        self.assertEqual(val["interface"]["client_id"], "r3oC")


if __name__ == "__main__":
    unittest.main()
