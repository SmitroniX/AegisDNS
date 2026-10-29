import unittest
from aegis.proxy import ProxyEndpoint, ProxyType, ProxyManager, SOCKS5Client


class TestProxyManager(unittest.TestCase):
    def setUp(self):
        self.pm = ProxyManager()

    def test_proxy_validation(self):
        # Valid SOCKS5
        p1 = ProxyEndpoint(name="socks_local", proxy_type=ProxyType.SOCKS5, host="127.0.0.1", port=1080)
        ok, err = p1.validate()
        self.assertTrue(ok)
        self.assertIsNone(err)

        # Invalid port
        p2 = ProxyEndpoint(name="bad_port", port=99999)
        ok2, err2 = p2.validate()
        self.assertFalse(ok2)
        self.assertIn("Invalid port", err2)

        # Unsupported type
        p3 = ProxyEndpoint(name="bad_type", proxy_type="SHADOWSOCKS")
        ok3, err3 = p3.validate()
        self.assertFalse(ok3)
        self.assertIn("Unsupported proxy type", err3)

    def test_default_proxy_and_domain_routing(self):
        p_default = ProxyEndpoint(name="default_proxy", port=1080, is_default=True)
        p_special = ProxyEndpoint(name="special_proxy", port=1081)

        self.pm.add_proxy(p_default)
        self.pm.add_proxy(p_special)

        # Default proxy selected when no domain mapping
        self.assertEqual(self.pm.route_target("generic.com").name, "default_proxy")

        # Map domain to special proxy
        self.pm.set_domain_proxy("internal.corp", "special_proxy")
        self.assertEqual(self.pm.route_target("internal.corp").name, "special_proxy")

    def test_socks5_connect_request_formats(self):
        # IPv4: ATYP 0x01, 4-byte IP, 2-byte port
        req_v4 = SOCKS5Client.build_connect_request("1.2.3.4", 80)
        self.assertEqual(req_v4[0:3], b"\x05\x01\x00")
        self.assertEqual(req_v4[3], 0x01)
        self.assertEqual(req_v4[4:8], bytes([1, 2, 3, 4]))
        self.assertEqual(req_v4[8:10], b"\x00\x50")

        # IPv6: ATYP 0x04, 16-byte IP, 2-byte port
        req_v6 = SOCKS5Client.build_connect_request("2001:db8::1", 443)
        self.assertEqual(req_v6[0:3], b"\x05\x01\x00")
        self.assertEqual(req_v6[3], 0x04)
        self.assertEqual(len(req_v6), 22)
        self.assertEqual(req_v6[20:22], b"\x01\xbb")

        # Domain: ATYP 0x03, 1-byte len, domain bytes, 2-byte port
        req_dom = SOCKS5Client.build_connect_request("example.com", 8080)
        self.assertEqual(req_dom[0:3], b"\x05\x01\x00")
        self.assertEqual(req_dom[3], 0x03)
        self.assertEqual(req_dom[4], len("example.com"))
        self.assertEqual(req_dom[5:5 + len("example.com")], b"example.com")


if __name__ == "__main__":
    unittest.main()
