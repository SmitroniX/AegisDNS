"""
Connection Tracker and Network Activity Logger for AegisDNS / RethinkCore.
Maintains active flow state, bandwidth counters, and connection history.
"""

from __future__ import annotations
import collections
import time
from typing import Dict, List, Optional, Tuple


class ConnectionFlow:
    def __init__(
        self,
        flow_id: str,
        app_id: str,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        domain: Optional[str] = None,
        action: str = "ALLOW",
        rule_reason: Optional[str] = None,
    ):
        self.flow_id = flow_id
        self.app_id = app_id
        self.protocol = protocol.upper()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.domain = domain
        self.action = action
        self.rule_reason = rule_reason
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.status = "ACTIVE" if action == "ALLOW" else "BLOCKED"

    def record_traffic(self, sent: int = 0, recv: int = 0):
        self.bytes_sent += sent
        self.bytes_recv += recv
        self.last_seen = time.time()

    def close(self):
        if self.status == "ACTIVE":
            self.status = "CLOSED"
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "app_id": self.app_id,
            "protocol": self.protocol,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "domain": self.domain,
            "action": self.action,
            "rule_reason": self.rule_reason,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "duration_s": round(self.last_seen - self.start_time, 2),
            "status": self.status,
            "start_time": self.start_time,
        }


class ConnectionTracker:
    def __init__(self, history_limit: int = 1000):
        self.active_flows: Dict[str, ConnectionFlow] = {}
        self.history: collections.deque = collections.deque(maxlen=history_limit)
        self.flow_counter = 0

    def start_flow(
        self,
        app_id: str,
        protocol: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        domain: Optional[str] = None,
        action: str = "ALLOW",
        rule_reason: Optional[str] = None,
    ) -> ConnectionFlow:
        self.flow_counter += 1
        flow_id = f"flow_{self.flow_counter}_{int(time.time() * 1000)}"
        flow = ConnectionFlow(
            flow_id=flow_id,
            app_id=app_id,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            domain=domain,
            action=action,
            rule_reason=rule_reason,
        )

        if action == "ALLOW":
            self.active_flows[flow_id] = flow
        else:
            self.history.appendleft(flow.to_dict())

        return flow

    def record_flow_traffic(self, flow_id: str, sent: int = 0, recv: int = 0) -> bool:
        if flow_id in self.active_flows:
            self.active_flows[flow_id].record_traffic(sent, recv)
            return True
        return False

    def close_flow(self, flow_id: str) -> bool:
        flow = self.active_flows.pop(flow_id, None)
        if flow:
            flow.close()
            self.history.appendleft(flow.to_dict())
            return True
        return False

    def get_active_flows(self) -> List[dict]:
        return [f.to_dict() for f in self.active_flows.values()]

    def get_history(self, limit: int = 100, app_id: Optional[str] = None) -> List[dict]:
        res = []
        for entry in self.history:
            if app_id and entry["app_id"] != app_id:
                continue
            res.append(entry)
            if len(res) >= limit:
                break
        return res

    def get_metrics(self) -> dict:
        total_tracked = self.flow_counter
        active_count = len(self.active_flows)
        blocked_count = sum(1 for e in self.history if e["action"] == "BLOCK")

        app_bytes = collections.defaultdict(int)
        for f in self.active_flows.values():
            app_bytes[f.app_id] += f.bytes_sent + f.bytes_recv
        for e in self.history:
            app_bytes[e["app_id"]] += e["bytes_sent"] + e["bytes_recv"]

        return {
            "total_tracked_flows": total_tracked,
            "active_flows": active_count,
            "blocked_flows": blocked_count,
            "top_apps_by_bandwidth": sorted(app_bytes.items(), key=lambda x: x[1], reverse=True)[:5],
        }
