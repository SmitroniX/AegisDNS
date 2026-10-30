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

    def test_cloudflare_warp_config_creation(self):
        warp = WireGuardConfig.create_cloudflare_warp_config()
        self.assertEqual(warp.name, "Cloudflare-WARP")
        self.assertEqual(warp.interface.mtu, 1280)
        self.assertEqual(warp.interface.addresses, ["172.16.0.2/32", "2606:4700:110:8f81:857e:8b9a:b042:d72b/128"])
        self.assertEqual(warp.peers[0].endpoint, "162.159.192.1:2408")
        self.assertEqual(warp.peers[0].allowed_ips, ["0.0.0.0/0", "::/0"])

        is_valid, errors = warp.validate()
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Roundtrip to INI string and parse back
        ini_str = warp.to_ini_string()
        parsed = WireGuardConfig.from_ini_string(ini_str)
        self.assertEqual(parsed.interface.mtu, 1280)
        self.assertEqual(parsed.peers[0].endpoint, "162.159.192.1:2408")

    def test_register_cloudflare_warp(self):
        # Live or fallback registration produces a valid ready-to-use profile
        warp = WireGuardConfig.register_cloudflare_warp(name="AutoWARP")
        self.assertEqual(warp.name, "AutoWARP")
        self.assertEqual(warp.interface.mtu, 1280)
        self.assertTrue(len(warp.interface.addresses) >= 1)
        self.assertTrue(len(warp.peers) == 1)
        is_valid, errors = warp.validate()
        self.assertTrue(is_valid, f"Validation errors: {errors}")

    def test_streaming_unblock_profile(self):
        profile = WireGuardConfig.create_streaming_unblock_profile(
            name="UK-BBC-Unblock",
            private_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            peer_public_key="YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
            endpoint="198.51.100.50:51820",
        )
        self.assertEqual(profile.name, "UK-BBC-Unblock")
        self.assertEqual(profile.interface.mtu, 1420)
        self.assertTrue(profile.validate()[0])


if __name__ == "__main__":
    unittest.main()
