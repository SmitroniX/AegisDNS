import unittest
from aegis.connection_tracker import ConnectionTracker


class TestConnectionTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = ConnectionTracker(history_limit=10)

    def test_start_and_close_flow(self):
        flow = self.tracker.start_flow(
            app_id="com.browser",
            protocol="TCP",
            src_ip="10.0.0.5",
            src_port=42100,
            dst_ip="93.184.216.34",
            dst_port=443,
            domain="example.com",
            action="ALLOW",
        )
        self.assertEqual(len(self.tracker.active_flows), 1)
        self.assertEqual(flow.status, "ACTIVE")

        # Record traffic
        self.tracker.record_flow_traffic(flow.flow_id, sent=500, recv=2000)
        self.assertEqual(flow.bytes_sent, 500)
        self.assertEqual(flow.bytes_recv, 2000)

        # Close flow
        ok = self.tracker.close_flow(flow.flow_id)
        self.assertTrue(ok)
        self.assertEqual(len(self.tracker.active_flows), 0)
        self.assertEqual(len(self.tracker.history), 1)

        history_entry = self.tracker.get_history()[0]
        self.assertEqual(history_entry["status"], "CLOSED")
        self.assertEqual(history_entry["bytes_sent"], 500)
        self.assertEqual(history_entry["bytes_recv"], 2000)

    def test_blocked_flow_goes_directly_to_history(self):
        flow = self.tracker.start_flow(
            app_id="com.tracker",
            protocol="UDP",
            src_ip="10.0.0.5",
            src_port=55000,
            dst_ip="198.51.100.1",
            dst_port=53,
            action="BLOCK",
            rule_reason="BLOCKED_IP",
        )
        self.assertEqual(len(self.tracker.active_flows), 0)
        self.assertEqual(len(self.tracker.history), 1)
        self.assertEqual(self.tracker.history[0]["status"], "BLOCKED")

    def test_metrics_aggregation(self):
        f1 = self.tracker.start_flow("app.one", "TCP", "10.0.0.2", 1000, "1.1.1.1", 443)
        self.tracker.record_flow_traffic(f1.flow_id, sent=1000, recv=4000)

        f2 = self.tracker.start_flow("app.two", "TCP", "10.0.0.2", 1001, "8.8.8.8", 53)
        self.tracker.record_flow_traffic(f2.flow_id, sent=200, recv=800)

        metrics = self.tracker.get_metrics()
        self.assertEqual(metrics["active_flows"], 2)
        top_apps = dict(metrics["top_apps_by_bandwidth"])
        self.assertEqual(top_apps["app.one"], 5000)
        self.assertEqual(top_apps["app.two"], 1000)


if __name__ == "__main__":
    unittest.main()
