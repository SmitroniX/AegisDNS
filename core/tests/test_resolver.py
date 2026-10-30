import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from aegis.dns_packet import DNSPacket, DNSQuestion, RecordType, RCode
from aegis.blocklist import BlocklistManager
from aegis.resolver import DNSResolver


class TestDNSResolver(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bl = BlocklistManager()
        self.bl.add_blocked_domain("malicious.test", wildcard=True, category="Malware")
        self.query_logs = []

        def log_cb(entry):
            self.query_logs.append(entry)

        self.resolver = DNSResolver(
            blocklist=self.bl,
            upstream_udp="1.1.1.1:53",
            cache_enabled=True,
            on_query_logged=log_cb,
        )

    async def test_blocked_domain_intercepted(self):
        req = DNSPacket()
        req.header.id = 999
        req.questions.append(DNSQuestion(qname="malicious.test", qtype=RecordType.A))

        resp = await self.resolver.resolve(req)

        self.assertEqual(resp.header.id, 999)
        self.assertEqual(resp.header.rcode, RCode.NOERROR)
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].rdata_str, "0.0.0.0")
        self.assertEqual(resp.answers[0].ttl, 60)

        # Verify query log
        self.assertEqual(len(self.query_logs), 1)
        self.assertTrue(self.query_logs[0]["blocked"])
        self.assertEqual(self.query_logs[0]["category"], "Malware")

    async def test_empty_question_returns_formerr(self):
        req = DNSPacket()
        resp = await self.resolver.resolve(req)
        self.assertEqual(resp.header.rcode, RCode.FORMERR)

    async def test_cache_hits(self):
        # Mock upstream query
        mock_resp = DNSPacket()
        mock_resp.header.id = 100
        mock_resp.questions.append(DNSQuestion(qname="clean.test", qtype=RecordType.A))
        mock_resp.add_a_record("clean.test", "1.2.3.4", ttl=300)

        self.resolver._query_udp = AsyncMock(return_value=mock_resp)

        req1 = DNSPacket()
        req1.header.id = 100
        req1.questions.append(DNSQuestion(qname="clean.test", qtype=RecordType.A))

        # First query -> hits upstream
        resp1 = await self.resolver.resolve(req1)
        self.assertEqual(resp1.answers[0].rdata_str, "1.2.3.4")
        self.assertEqual(self.resolver.stats["upstream_queries"], 1)
        self.assertEqual(self.resolver.stats["cached_queries"], 0)

        # Second query -> hits cache
        req2 = DNSPacket()
        req2.header.id = 101
        req2.questions.append(DNSQuestion(qname="clean.test", qtype=RecordType.A))

        resp2 = await self.resolver.resolve(req2)
        self.assertEqual(resp2.header.id, 101)
        self.assertEqual(resp2.answers[0].rdata_str, "1.2.3.4")
        self.assertEqual(self.resolver.stats["upstream_queries"], 1)
        self.assertEqual(self.resolver.stats["cached_queries"], 1)

    async def test_blocked_domain_aaaa_query_returns_ipv6(self):
        req = DNSPacket()
        req.header.id = 777
        req.questions.append(DNSQuestion(qname="malicious.test", qtype=RecordType.AAAA))

        resp = await self.resolver.resolve(req)
        self.assertEqual(resp.header.rcode, RCode.NOERROR)
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].rtype, RecordType.AAAA)
        self.assertEqual(resp.answers[0].rdata_str, "::")

    async def test_blocked_domain_txt_query_returns_nodata(self):
        req = DNSPacket()
        req.header.id = 888
        req.questions.append(DNSQuestion(qname="malicious.test", qtype=RecordType.TXT))

        resp = await self.resolver.resolve(req)
        self.assertEqual(resp.header.rcode, RCode.NOERROR)
        self.assertEqual(len(resp.answers), 0)

    async def test_cache_ttl_decrement(self):
        import time
        from aegis.resolver import CacheEntry

        mock_resp = DNSPacket()
        mock_resp.add_a_record("decay.test", "1.1.1.1", ttl=300)
        # Entry expires in 50 seconds (i.e. 250s already elapsed)
        self.resolver.cache[("decay.test", RecordType.A)] = CacheEntry(mock_resp, time.time() + 50)

        query = DNSPacket()
        query.questions.append(DNSQuestion(qname="decay.test", qtype=RecordType.A))

        resp = await self.resolver.resolve(query)
        self.assertLessEqual(resp.answers[0].ttl, 50)
        self.assertGreater(resp.answers[0].ttl, 40)

    def test_parse_upstream_addr_formats(self):
        h1, p1 = self.resolver._parse_upstream_addr("1.1.1.1")
        self.assertEqual((h1, p1), ("1.1.1.1", 53))

        h2, p2 = self.resolver._parse_upstream_addr("1.1.1.1:5353")
        self.assertEqual((h2, p2), ("1.1.1.1", 5353))

        h3, p3 = self.resolver._parse_upstream_addr("[2606:4700:4700::1111]:53")
        self.assertEqual((h3, p3), ("2606:4700:4700::1111", 53))

        h4, p4 = self.resolver._parse_upstream_addr("2606:4700:4700::1111")
        self.assertEqual((h4, p4), ("2606:4700:4700::1111", 53))

    def test_default_upstream_is_adguard(self):
        from aegis.resolver import DEFAULT_UPSTREAM_UDP, DNS_PRESETS
        default_res = DNSResolver()
        self.assertEqual(default_res.upstream_udp, DEFAULT_UPSTREAM_UDP)
        self.assertEqual(default_res.upstream_udp, "94.140.15.15:53")
        self.assertIn("adguard", DNS_PRESETS)
        self.assertEqual(DNS_PRESETS["adguard"]["udp"], "94.140.15.15:53")

    def test_preset_selection(self):
        cf_res = DNSResolver(preset="cloudflare")
        self.assertEqual(cf_res.upstream_udp, "1.1.1.1:53")
        self.assertEqual(cf_res.upstream_doh, "https://cloudflare-dns.com/dns-query")

        adguard_res = DNSResolver(preset="adguard")
        self.assertEqual(adguard_res.upstream_udp, "94.140.15.15:53")
        self.assertEqual(adguard_res.upstream_doh, "https://dns.adguard-dns.com/dns-query")

    async def test_domain_split_dns_routing_exact(self):
        # Route hotstar.com directly to AdGuard to skip ads
        self.resolver.add_split_rule("hotstar.com", upstream_udp="94.140.15.15:53", description="AdGuard for Hotstar")

        mock_resp = DNSPacket()
        mock_resp.add_a_record("hotstar.com", "13.235.12.34", ttl=300)
        self.resolver._query_udp = AsyncMock(return_value=mock_resp)

        query = DNSPacket()
        query.questions.append(DNSQuestion(qname="hotstar.com", qtype=RecordType.A))
        resp = await self.resolver.resolve(query)

        self.assertEqual(resp.answers[0].rdata_str, "13.235.12.34")
        self.resolver._query_udp.assert_awaited_with(query, "94.140.15.15:53")
        self.assertEqual(self.query_logs[-1]["upstream"], "SPLIT_DNS:94.140.15.15:53")
        self.assertEqual(self.resolver.stats["split_queries"], 1)

    async def test_domain_split_dns_routing_wildcard(self):
        # Route *.hotstar.com to AdGuard
        self.resolver.add_split_rule("*.hotstar.com", upstream_udp="94.140.15.15:53")

        mock_resp_split = DNSPacket()
        mock_resp_split.add_a_record("api.hotstar.com", "13.235.12.35", ttl=300)

        mock_resp_def = DNSPacket()
        mock_resp_def.add_a_record("google.com", "142.250.190.46", ttl=300)

        async def mock_query(pkt, addr):
            if "hotstar" in pkt.questions[0].name:
                return mock_resp_split
            return mock_resp_def

        self.resolver._query_udp = AsyncMock(side_effect=mock_query)

        # 1. Subdomain of hotstar.com matches split rule
        q1 = DNSPacket()
        q1.questions.append(DNSQuestion(qname="api.hotstar.com", qtype=RecordType.A))
        await self.resolver.resolve(q1)
        self.assertEqual(self.query_logs[-1]["upstream"], "SPLIT_DNS:94.140.15.15:53")

        # 2. General domain uses default upstream
        q2 = DNSPacket()
        q2.questions.append(DNSQuestion(qname="google.com", qtype=RecordType.A))
        await self.resolver.resolve(q2)
        self.assertEqual(self.query_logs[-1]["upstream"], "1.1.1.1:53")

    async def test_streaming_split_dns_presets_load(self):
        count = self.resolver.load_streaming_split_presets(["hotstar", "netflix", "bbc_iplayer"])
        self.assertGreater(count, 0)
        self.assertIsNotNone(self.resolver.get_split_rule("api.hotstar.com"))
        self.assertIsNotNone(self.resolver.get_split_rule("video.netflix.com"))
        self.assertIsNotNone(self.resolver.get_split_rule("tv.bbc.co.uk"))

    async def test_remove_split_rule(self):
        self.resolver.add_split_rule("custom.streaming.tv", upstream_udp="8.8.4.4:53")
        self.assertIsNotNone(self.resolver.get_split_rule("custom.streaming.tv"))

        removed = self.resolver.remove_split_rule("custom.streaming.tv")
        self.assertTrue(removed)
        self.assertIsNone(self.resolver.get_split_rule("custom.streaming.tv"))


if __name__ == "__main__":
    unittest.main()
