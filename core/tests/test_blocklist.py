import unittest
from aegis.blocklist import BlocklistManager


class TestBlocklistManager(unittest.TestCase):
    def setUp(self):
        self.bl = BlocklistManager()

    def test_exact_domain_blocking(self):
        self.bl.add_blocked_domain("badads.com", wildcard=False, category="Ads")
        blocked, rule, cat = self.bl.is_domain_blocked("badads.com")
        self.assertTrue(blocked)
        self.assertEqual(rule, "badads.com")
        self.assertEqual(cat, "Ads")

        # Subdomain should NOT be blocked if exact match only
        blocked_sub, _, _ = self.bl.is_domain_blocked("sub.badads.com")
        self.assertFalse(blocked_sub)

    def test_wildcard_domain_blocking(self):
        self.bl.add_blocked_domain("doubleclick.net", wildcard=True, category="Trackers")
        blocked_root, rule, _ = self.bl.is_domain_blocked("doubleclick.net")
        self.assertTrue(blocked_root)
        self.assertEqual(rule, "*.doubleclick.net")

        blocked_sub, rule_sub, _ = self.bl.is_domain_blocked("ad.doubleclick.net")
        self.assertTrue(blocked_sub)
        self.assertEqual(rule_sub, "*.doubleclick.net")

        blocked_deep, _, _ = self.bl.is_domain_blocked("deep.nested.ad.doubleclick.net")
        self.assertTrue(blocked_deep)

        # Unrelated domain should be allowed
        unrelated, _, _ = self.bl.is_domain_blocked("click.net")
        self.assertFalse(unrelated)

    def test_allowlist_precedence(self):
        self.bl.add_blocked_domain("example.com", wildcard=True)
        self.bl.add_allowed_domain("safe.example.com", wildcard=False)

        blocked_safe, _, _ = self.bl.is_domain_blocked("safe.example.com")
        self.assertFalse(blocked_safe)

        blocked_other, _, _ = self.bl.is_domain_blocked("other.example.com")
        self.assertTrue(blocked_other)

    def test_hosts_file_parsing(self):
        hosts_content = """
        # Sample hosts
        0.0.0.0 ad1.com
        127.0.0.1 ad2.org ad3.net
        ::1 localhost
        """
        loaded = self.bl.load_from_text(hosts_content, default_category="hosts")
        self.assertEqual(loaded, 3)

        self.assertTrue(self.bl.is_domain_blocked("ad1.com")[0])
        self.assertTrue(self.bl.is_domain_blocked("ad2.org")[0])
        self.assertTrue(self.bl.is_domain_blocked("ad3.net")[0])
        self.assertFalse(self.bl.is_domain_blocked("localhost")[0])

    def test_adblock_syntax_parsing(self):
        adblock_content = """
        ! Adblock comment
        ||adserver.com^
        ||tracking.net^
        ||analytics.io^$third-party
        ||telemetry.org
        @@||allowed.com^
        """
        loaded = self.bl.load_from_text(adblock_content)
        self.assertEqual(loaded, 5)

        self.assertTrue(self.bl.is_domain_blocked("adserver.com")[0])
        self.assertTrue(self.bl.is_domain_blocked("sub.adserver.com")[0])
        self.assertTrue(self.bl.is_domain_blocked("tracking.net")[0])
        self.assertTrue(self.bl.is_domain_blocked("analytics.io")[0])
        self.assertTrue(self.bl.is_domain_blocked("telemetry.org")[0])
        self.assertTrue(self.bl.is_domain_allowed("allowed.com"))
        self.assertTrue(self.bl.is_domain_allowed("sub.allowed.com"))
        self.assertFalse(self.bl.is_domain_blocked("allowed.com")[0])

    def test_ip_cidr_blocking(self):
        self.bl.add_blocked_ip_or_cidr("198.51.100.0/24", category="MalwareIP")
        blocked, net = self.bl.is_ip_blocked("198.51.100.42")
        self.assertTrue(blocked)
        self.assertEqual(net, "198.51.100.0/24")

        blocked_safe, _ = self.bl.is_ip_blocked("198.51.101.1")
        self.assertFalse(blocked_safe)


if __name__ == "__main__":
    unittest.main()
