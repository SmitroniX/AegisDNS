"""
Firewall Rules Engine for AegisDNS / RethinkCore.
Models per-app, per-network (metered vs unmetered), per-protocol,
and CIDR IP rules with real-time packet/connection evaluation.
"""

from __future__ import annotations
import ipaddress
import time
from typing import Dict, List, Optional, Set, Tuple


class FirewallAction:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"
    BYPASS = "BYPASS"


class NetworkType:
    ANY = "ANY"
    METERED = "METERED"      # e.g. Cellular / Mobile data
    UNMETERED = "UNMETERED"  # e.g. Wi-Fi / Ethernet


class FirewallRule:
    def __init__(
        self,
        rule_id: str,
        action: str = FirewallAction.BLOCK,
        app_id: Optional[str] = None,          # Package name or app identifier
        network_type: str = NetworkType.ANY,    # ANY, METERED, UNMETERED
        block_background: bool = False,
        protocol: Optional[str] = None,         # TCP, UDP, ICMP, ANY
        dest_cidr: Optional[str] = None,        # e.g. 192.168.1.0/24
        dest_port: Optional[int] = None,        # e.g. 80, 443
        domain: Optional[str] = None,
        description: str = "",
    ):
        self.rule_id = rule_id
        self.action = action.upper()
        self.app_id = app_id
        self.network_type = network_type.upper()
        self.block_background = block_background
        self.protocol = protocol.upper() if protocol else None
        self.dest_cidr = dest_cidr
        self._parsed_net = ipaddress.ip_network(dest_cidr.strip(), strict=False) if dest_cidr else None
        self.dest_port = dest_port
        self.domain = domain.lower() if domain else None
        self.description = description
        self.created_at = time.time()
        self.hit_count = 0

    def matches(
        self,
        app_id: Optional[str] = None,
        network_type: str = NetworkType.UNMETERED,
        is_background: bool = False,
        protocol: str = "TCP",
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        domain: Optional[str] = None,
    ) -> bool:
        # Check app
        if self.app_id and self.app_id != app_id:
            return False

        # Check network type
        if self.network_type != NetworkType.ANY and self.network_type != network_type:
            return False

        # Check background constraint
        if self.block_background and not is_background:
            return False

        # Check protocol
        if self.protocol and self.protocol != "ANY" and self.protocol != protocol.upper():
            return False

        # Check port
        if self.dest_port is not None and self.dest_port != dest_port:
            return False

        # Check IP/CIDR constraint
        if self._parsed_net:
            if not dest_ip:
                return False
            try:
                ip = ipaddress.ip_address(dest_ip)
                if ip not in self._parsed_net:
                    return False
            except ValueError:
                return False

        # Check domain constraint
        if self.domain:
            if not domain:
                return False
            d_norm = domain.rstrip(".").lower()
            if self.domain.startswith("*."):
                suffix = self.domain[2:]
                if not (d_norm == suffix or d_norm.endswith("." + suffix)):
                    return False
            elif self.domain != d_norm:
                return False

        self.hit_count += 1
        return True


class FirewallManager:
    def __init__(self, default_action: str = FirewallAction.ALLOW):
        self.default_action = default_action
        self.rules: Dict[str, FirewallRule] = {}
        self.isolated_apps: Set[str] = set()
        self.lockdown_mode: bool = False
        self.current_network_type: str = NetworkType.UNMETERED

    def set_network_type(self, network_type: str):
        self.current_network_type = network_type.upper()

    def set_lockdown_mode(self, enabled: bool):
        self.lockdown_mode = enabled

    def add_rule(self, rule: FirewallRule) -> str:
        self.rules[rule.rule_id] = rule
        return rule.rule_id

    def remove_rule(self, rule_id: str) -> bool:
        return bool(self.rules.pop(rule_id, None))

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        return self.rules.get(rule_id)

    def list_rules(self) -> List[dict]:
        return [
            {
                "rule_id": r.rule_id,
                "action": r.action,
                "app_id": r.app_id,
                "network_type": r.network_type,
                "block_background": r.block_background,
                "protocol": r.protocol,
                "dest_cidr": r.dest_cidr,
                "dest_port": r.dest_port,
                "domain": r.domain,
                "description": r.description,
                "hit_count": r.hit_count,
            }
            for r in self.rules.values()
        ]

    def isolate_app(self, app_id: str, isolate: bool = True):
        if isolate:
            self.isolated_apps.add(app_id)
        else:
            self.isolated_apps.discard(app_id)

    def evaluate(
        self,
        app_id: Optional[str] = None,
        is_background: bool = False,
        protocol: str = "TCP",
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        domain: Optional[str] = None,
    ) -> Tuple[str, Optional[str]]:
        """
        Evaluates connection against firewall policies.
        Returns: (FirewallAction, matched_rule_id_or_reason)
        """
        # 1. Check Global Lockdown
        if self.lockdown_mode:
            return FirewallAction.BLOCK, "LOCKDOWN_MODE"

        # 2. Check App Isolation
        if app_id and app_id in self.isolated_apps:
            # Isolated apps can only access local or loopback addresses
            if dest_ip not in ("127.0.0.1", "::1", "localhost"):
                return FirewallAction.BLOCK, "APP_ISOLATED"

        # 3. Check explicit Rules
        # First priority: explicit ALLOW rules
        for r in self.rules.values():
            if r.action == FirewallAction.ALLOW and r.matches(
                app_id=app_id,
                network_type=self.current_network_type,
                is_background=is_background,
                protocol=protocol,
                dest_ip=dest_ip,
                dest_port=dest_port,
                domain=domain,
            ):
                return FirewallAction.ALLOW, r.rule_id

        # Second priority: explicit BLOCK rules
        for r in self.rules.values():
            if r.action == FirewallAction.BLOCK and r.matches(
                app_id=app_id,
                network_type=self.current_network_type,
                is_background=is_background,
                protocol=protocol,
                dest_ip=dest_ip,
                dest_port=dest_port,
                domain=domain,
            ):
                return FirewallAction.BLOCK, r.rule_id

        # Third priority: ISOLATE / BYPASS
        for r in self.rules.values():
            if r.action in (FirewallAction.ISOLATE, FirewallAction.BYPASS) and r.matches(
                app_id=app_id,
                network_type=self.current_network_type,
                is_background=is_background,
                protocol=protocol,
                dest_ip=dest_ip,
                dest_port=dest_port,
                domain=domain,
            ):
                return r.action, r.rule_id

        # 4. Default policy fallback
        return self.default_action, "DEFAULT_POLICY"
