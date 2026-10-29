import unittest
from aegis.wireguard import (
    WireGuardConfig,
    WireGuardInterface,
    WireGuardPeer,
    is_valid_base64_key,
)


class TestWireGuardConfig(unittest.TestCase):
    def test_base64_key_validation(self):
        # 32 bytes base64 encoded = 44 characters ending with '='
        valid_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        self.assertTrue(is_valid_base64_key(valid_key))

        # Too short
        self.assertFalse(is_valid_base64_key("shortkey="))
        # Not base64
        self.assertFalse(is_valid_base64_key("???!!!======================================"))

    def test_parse_valid_ini_config(self):
        ini_content = """
        [Interface]
        PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
        Address = 10.0.0.2/32, fd00::2/128
        DNS = 1.1.1.1, 8.8.8.8
        MTU = 1420
        ListenPort = 51820

        [Peer]
        PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
        Endpoint = 198.51.100.1:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """
        cfg = WireGuardConfig.from_ini_string(ini_content, name="profile1")
        self.assertEqual(cfg.name, "profile1")
        self.assertEqual(cfg.interface.mtu, 1420)
        self.assertEqual(cfg.interface.addresses, ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(len(cfg.peers), 1)

        peer = cfg.peers[0]
        self.assertEqual(peer.endpoint, "198.51.100.1:51820")
        self.assertEqual(peer.persistent_keepalive, 25)

        is_valid, errors = cfg.validate()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_invalid_peer_endpoint_fails_validation(self):
        ini_content = """
        [Interface]
        PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
        Address = 10.0.0.2/32

        [Peer]
        PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
        Endpoint = invalid_no_port
        AllowedIPs = 999.999.999.999/99
        """
        cfg = WireGuardConfig.from_ini_string(ini_content)
        is_valid, errors = cfg.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Endpoint" in e for e in errors))
        self.assertTrue(any("AllowedIPs" in e for e in errors))

    def test_multiline_directives_parsing(self):
        ini_content = """
        [Interface]
        PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
        Address = 10.0.0.2/32
        Address = fd00::2/128
        DNS = 1.1.1.1
        DNS = 8.8.8.8

        [Peer]
        PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
        AllowedIPs = 10.0.0.0/8
        AllowedIPs = 192.168.0.0/16
        """
        cfg = WireGuardConfig.from_ini_string(ini_content)
        self.assertEqual(cfg.interface.addresses, ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(cfg.interface.dns_servers, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(cfg.peers[0].allowed_ips, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_bracketed_ipv6_endpoint(self):
        peer = WireGuardPeer(
            public_key="YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
            endpoint="[2606:4700::1]:51820",
        )
        self.assertEqual(peer.validate(), [])

    def test_roundtrip_serialization(self):
        iface = WireGuardInterface(
            private_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            addresses=["10.0.0.5/32"],
            dns_servers=["9.9.9.9"],
            mtu=1280,
        )
        peer = WireGuardPeer(
            public_key="YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
            endpoint="1.2.3.4:51820",
            allowed_ips=["0.0.0.0/0"],
        )
        cfg = WireGuardConfig(name="roundtrip", interface=iface, peers=[peer])

        ini_text = cfg.to_ini_string()
        cfg2 = WireGuardConfig.from_ini_string(ini_text, name="roundtrip")
        self.assertEqual(cfg2.interface.mtu, 1280)
        self.assertEqual(cfg2.peers[0].endpoint, "1.2.3.4:51820")


if __name__ == "__main__":
    unittest.main()
