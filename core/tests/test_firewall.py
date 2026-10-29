import unittest
from aegis.firewall import FirewallManager, FirewallRule, FirewallAction, NetworkType


class TestFirewallManager(unittest.TestCase):
    def setUp(self):
        self.fw = FirewallManager(default_action=FirewallAction.ALLOW)

    def test_default_policy(self):
        action, reason = self.fw.evaluate(app_id="org.mozilla.firefox", dest_ip="1.1.1.1", dest_port=443)
        self.assertEqual(action, FirewallAction.ALLOW)
        self.assertEqual(reason, "DEFAULT_POLICY")

    def test_global_lockdown(self):
        self.fw.set_lockdown_mode(True)
        action, reason = self.fw.evaluate(app_id="org.mozilla.firefox", dest_ip="1.1.1.1", dest_port=443)
        self.assertEqual(action, FirewallAction.BLOCK)
        self.assertEqual(reason, "LOCKDOWN_MODE")

    def test_app_isolation(self):
        self.fw.isolate_app("com.untrusted.app", True)

        # Access to WAN blocked
        action, reason = self.fw.evaluate(app_id="com.untrusted.app", dest_ip="8.8.8.8")
        self.assertEqual(action, FirewallAction.BLOCK)
        self.assertEqual(reason, "APP_ISOLATED")

        # Access to localhost allowed
        action_local, _ = self.fw.evaluate(app_id="com.untrusted.app", dest_ip="127.0.0.1")
        self.assertEqual(action_local, FirewallAction.ALLOW)

    def test_metered_network_rule(self):
        # Block video streaming app when on METERED mobile network
        rule = FirewallRule(
            rule_id="block_stream_mobile",
            action=FirewallAction.BLOCK,
            app_id="com.video.stream",
            network_type=NetworkType.METERED,
        )
        self.fw.add_rule(rule)

        # On Wi-Fi (UNMETERED): should be ALLOWED
        self.fw.set_network_type(NetworkType.UNMETERED)
        action_wifi, _ = self.fw.evaluate(app_id="com.video.stream", dest_ip="1.2.3.4")
        self.assertEqual(action_wifi, FirewallAction.ALLOW)

        # On Cellular (METERED): should be BLOCKED
        self.fw.set_network_type(NetworkType.METERED)
        action_cell, reason_cell = self.fw.evaluate(app_id="com.video.stream", dest_ip="1.2.3.4")
        self.assertEqual(action_cell, FirewallAction.BLOCK)
        self.assertEqual(reason_cell, "block_stream_mobile")

    def test_cidr_ip_subnet_blocking(self):
        rule = FirewallRule(
            rule_id="block_bad_subnet",
            action=FirewallAction.BLOCK,
            dest_cidr="198.51.100.0/24",
        )
        self.fw.add_rule(rule)

        action, r_id = self.fw.evaluate(dest_ip="198.51.100.55")
        self.assertEqual(action, FirewallAction.BLOCK)
        self.assertEqual(r_id, "block_bad_subnet")

        action_safe, _ = self.fw.evaluate(dest_ip="198.51.101.1")
        self.assertEqual(action_safe, FirewallAction.ALLOW)

    def test_background_restriction(self):
        rule = FirewallRule(
            rule_id="block_bg_sync",
            action=FirewallAction.BLOCK,
            app_id="com.social.app",
            block_background=True,
        )
        self.fw.add_rule(rule)

        # When foreground: ALLOW
        act_fg, _ = self.fw.evaluate(app_id="com.social.app", is_background=False)
        self.assertEqual(act_fg, FirewallAction.ALLOW)

        # When background: BLOCK
        act_bg, r_bg = self.fw.evaluate(app_id="com.social.app", is_background=True)
        self.assertEqual(act_bg, FirewallAction.BLOCK)
        self.assertEqual(r_bg, "block_bg_sync")

    def test_cidr_does_not_match_when_dest_ip_missing(self):
        rule = FirewallRule("cidr_rule", action=FirewallAction.BLOCK, dest_cidr="10.0.0.0/8")
        self.fw.add_rule(rule)

        # Connection with domain but no dest_ip should NOT match CIDR rule
        action, _ = self.fw.evaluate(domain="google.com", dest_ip=None)
        self.assertEqual(action, FirewallAction.ALLOW)

    def test_domain_rule_does_not_match_when_domain_missing(self):
        rule = FirewallRule("domain_rule", action=FirewallAction.BLOCK, domain="evil.com")
        self.fw.add_rule(rule)

        # Connection with IP but no domain should NOT match domain rule
        action, _ = self.fw.evaluate(dest_ip="8.8.8.8", domain=None)
        self.assertEqual(action, FirewallAction.ALLOW)


if __name__ == "__main__":
    unittest.main()
