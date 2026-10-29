import asyncio
import json
import urllib.request
import unittest
from aegis.service import AegisService
from aegis.api import AegisApiServer
from aegis.dns_packet import RecordType


class TestAegisApiServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.service = AegisService()
        self.service.blocklist.add_blocked_domain("telemetry.bad.org", wildcard=True)

        self.api_port = 18053
        self.api = AegisApiServer(self.service, host="127.0.0.1", port=self.api_port)
        await self.api.start()

    async def asyncTearDown(self):
        await self.api.stop()

    def _http_get(self, path: str):
        url = f"http://127.0.0.1:{self.api_port}{path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)

    def _http_post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:{self.api_port}{path}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)

    def _http_delete(self, path: str):
        url = f"http://127.0.0.1:{self.api_port}{path}"
        req = urllib.request.Request(url, method="DELETE")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)

    async def test_health_endpoint(self):
        status, data = await asyncio.to_thread(self._http_get, "/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "AegisDNS")

    async def test_stats_endpoint(self):
        status, data = await asyncio.to_thread(self._http_get, "/stats")
        self.assertEqual(status, 200)
        self.assertIn("dns", data)
        self.assertIn("firewall", data)
        self.assertIn("connections", data)

    async def test_resolve_endpoint_blocked(self):
        status, data = await asyncio.to_thread(
            self._http_post, "/dns/resolve", {"domain": "telemetry.bad.org", "qtype": 1}
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["blocked"])
        self.assertEqual(data["answers"][0]["data"], "0.0.0.0")

    async def test_firewall_rule_crud(self):
        # Add rule
        rule_payload = {
            "rule_id": "block_social_app",
            "action": "BLOCK",
            "app_id": "com.social.network",
            "description": "Block social app",
        }
        status, data = await asyncio.to_thread(self._http_post, "/rules/firewall", rule_payload)
        self.assertEqual(status, 201)
        self.assertEqual(data["rule_id"], "block_social_app")

        # List rules
        status_list, list_data = await asyncio.to_thread(self._http_get, "/rules/firewall")
        self.assertEqual(status_list, 200)
        self.assertTrue(any(r["rule_id"] == "block_social_app" for r in list_data["rules"]))

        # Delete rule
        status_del, del_data = await asyncio.to_thread(self._http_delete, "/rules/firewall/block_social_app")
        self.assertEqual(status_del, 200)
        self.assertEqual(del_data["status"], "deleted")


if __name__ == "__main__":
    unittest.main()
