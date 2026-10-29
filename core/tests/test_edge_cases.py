import unittest
from aegis.dns_packet import DNSPacket, encode_dns_name, decode_dns_name, DNSHeader
from aegis.blocklist import BlocklistManager
from aegis.firewall import FirewallManager, FirewallRule, FirewallAction
from aegis.wireguard import WireGuardConfig, is_valid_base64_key
from aegis.proxy import ProxyEndpoint, ProxyManager, SOCKS5Client


class TestEdgeCases(unittest.TestCase):
    def test_dns_name_empty_and_root(self):
        enc_empty = encode_dns_name("")
        self.assertEqual(enc_empty, b"\x00")
        name, off = decode_dns_name(enc_empty, 0)
        self.assertEqual(name, "")

        enc_root = encode_dns_name(".")
        self.assertEqual(enc_root, b"\x00")

    def test_dns_label_exceeding_max_length(self):
        long_label = "a" * 64
        with self.assertRaises(ValueError):
            encode_dns_name(f"{long_label}.com")

    def test_malformed_truncated_dns_packet(self):
        with self.assertRaises(ValueError):
            DNSPacket.from_bytes(b"")
        with self.assertRaises(ValueError):
            DNSPacket.from_bytes(b"\x00" * 5)

    def test_blocklist_whitespace_case_trailing_dots(self):
        bl = BlocklistManager()
        bl.add_blocked_domain("   Ads.DoubleClick.Net.  ", wildcard=True)

        self.assertTrue(bl.is_domain_blocked("ads.doubleclick.net")[0])
        self.assertTrue(bl.is_domain_blocked("ADS.DOUBLECLICK.NET.")[0])
        self.assertTrue(bl.is_domain_blocked("sub.ads.doubleclick.net")[0])
        self.assertFalse(bl.is_domain_blocked("")[0])

    def test_firewall_invalid_dest_ip(self):
        fw = FirewallManager(default_action=FirewallAction.ALLOW)
        rule = FirewallRule("rule1", action=FirewallAction.BLOCK, dest_cidr="10.0.0.0/8")
        fw.add_rule(rule)

        # Invalid IP string should not crash evaluation, should simply not match
        action, _ = fw.evaluate(dest_ip="not_an_ip")
        self.assertEqual(action, FirewallAction.ALLOW)

    def test_wireguard_key_edge_cases(self):
        self.assertFalse(is_valid_base64_key(""))
        self.assertFalse(is_valid_base64_key(" " * 44))
        self.assertFalse(is_valid_base64_key("A" * 43))
        self.assertFalse(is_valid_base64_key("A" * 45))

    def test_socks5_payload_generation(self):
        handshake = SOCKS5Client.build_handshake("user", "pass")
        self.assertEqual(handshake, b"\x05\x02\x00\x02")

        auth = SOCKS5Client.build_auth_payload("admin", "secret")
        self.assertEqual(auth[0], 0x01)
        self.assertIn(b"admin", auth)
        self.assertIn(b"secret", auth)

        conn_ipv4 = SOCKS5Client.build_connect_request("1.1.1.1", 53)
        self.assertEqual(conn_ipv4[:4], b"\x05\x01\x00\x01")

        conn_ipv6 = SOCKS5Client.build_connect_request("2001:db8::1", 443)
        self.assertEqual(conn_ipv6[:4], b"\x05\x01\x00\x04")
        self.assertEqual(len(conn_ipv6), 22)

        conn_domain = SOCKS5Client.build_connect_request("example.com", 443)
        self.assertEqual(conn_domain[:4], b"\x05\x01\x00\x03")
        self.assertEqual(conn_domain[4], len("example.com"))


if __name__ == "__main__":
    unittest.main()
