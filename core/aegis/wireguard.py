"""
WireGuard Configuration Parser, Validator, and Manager for AegisDNS / RethinkCore.
Handles standard WireGuard INI config syntax, Curve25519 key validation,
AllowedIPs CIDR verification, and multi-peer profiles.
"""

from __future__ import annotations
import base64
import collections
import configparser
import io
import ipaddress
import re
from typing import List, Optional, Dict, Tuple


def is_valid_base64_key(key: str) -> bool:
    """WireGuard keys are Curve25519 32-byte keys encoded in standard Base64 (44 chars)."""
    key = key.strip()
    if len(key) != 44 or not key.endswith("="):
        return False
    try:
        raw = base64.b64decode(key, validate=True)
        return len(raw) == 32
    except Exception:
        return False


class WireGuardPeer:
    def __init__(
        self,
        public_key: str,
        endpoint: Optional[str] = None,
        allowed_ips: Optional[List[str]] = None,
        preshared_key: Optional[str] = None,
        persistent_keepalive: Optional[int] = None,
    ):
        self.public_key = public_key.strip()
        self.endpoint = endpoint.strip() if endpoint else None
        self.allowed_ips: List[str] = allowed_ips or ["0.0.0.0/0", "::/0"]
        self.preshared_key = preshared_key.strip() if preshared_key else None
        self.persistent_keepalive = persistent_keepalive

    def validate(self) -> List[str]:
        errors = []
        if not is_valid_base64_key(self.public_key):
            errors.append(f"Invalid PublicKey format: '{self.public_key}'")

        if self.preshared_key and not is_valid_base64_key(self.preshared_key):
            errors.append(f"Invalid PresharedKey format: '{self.preshared_key}'")

        if self.endpoint:
            ep = self.endpoint.strip()
            if ep.startswith("["):
                end_b = ep.find("]")
                if end_b == -1 or not ep[end_b + 1 :].startswith(":"):
                    errors.append(f"Invalid bracketed IPv6 endpoint format: '{self.endpoint}', expected [host]:port")
                else:
                    try:
                        port = int(ep[end_b + 1 :].lstrip(":"))
                        if not (1 <= port <= 65535):
                            errors.append(f"Invalid Endpoint port: {port}")
                    except ValueError:
                        errors.append(f"Invalid Endpoint port in '{self.endpoint}'")
            else:
                parts = ep.rsplit(":", 1)
                if len(parts) != 2:
                    errors.append(f"Invalid Endpoint format: '{self.endpoint}', expected host:port")
                else:
                    try:
                        port = int(parts[1])
                        if not (1 <= port <= 65535):
                            errors.append(f"Invalid Endpoint port: {port}")
                    except ValueError:
                        errors.append(f"Invalid Endpoint port: '{parts[1]}'")

        for cidr in self.allowed_ips:
            try:
                ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                errors.append(f"Invalid AllowedIPs network: '{cidr}'")

        return errors

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key,
            "endpoint": self.endpoint,
            "allowed_ips": self.allowed_ips,
            "has_psk": bool(self.preshared_key),
            "persistent_keepalive": self.persistent_keepalive,
        }


class WireGuardInterface:
    def __init__(
        self,
        private_key: str,
        addresses: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
        mtu: int = 1420,
        listen_port: Optional[int] = None,
    ):
        self.private_key = private_key.strip()
        self.addresses: List[str] = addresses or []
        self.dns_servers: List[str] = dns_servers or ["1.1.1.1"]
        self.mtu = mtu
        self.listen_port = listen_port

    def validate(self) -> List[str]:
        errors = []
        if not is_valid_base64_key(self.private_key):
            errors.append("Invalid PrivateKey format in Interface")

        for addr in self.addresses:
            try:
                ipaddress.ip_interface(addr.strip())
            except ValueError:
                errors.append(f"Invalid Interface Address: '{addr}'")

        if not (576 <= self.mtu <= 65535):
            errors.append(f"Invalid MTU size: {self.mtu}")

        return errors

    def to_dict(self) -> dict:
        return {
            "addresses": self.addresses,
            "dns_servers": self.dns_servers,
            "mtu": self.mtu,
            "listen_port": self.listen_port,
        }


class WireGuardConfig:
    def __init__(
        self,
        name: str,
        interface: WireGuardInterface,
        peers: Optional[List[WireGuardPeer]] = None,
    ):
        self.name = name
        self.interface = interface
        self.peers = peers or []

    def validate(self) -> Tuple[bool, List[str]]:
        errors = self.interface.validate()
        for i, peer in enumerate(self.peers):
            peer_errors = peer.validate()
            for err in peer_errors:
                errors.append(f"Peer {i + 1}: {err}")
        return len(errors) == 0, errors

    @classmethod
    def from_ini_string(cls, text: str, name: str = "custom") -> WireGuardConfig:
        """Parses standard multi-section WireGuard .conf file."""
        lines = text.strip().splitlines()
        interface_params: Dict[str, List[str]] = collections.defaultdict(list)
        peers: List[WireGuardPeer] = []
        current_section = None
        current_peer_params: Dict[str, List[str]] = collections.defaultdict(list)

        def flush_peer():
            nonlocal current_peer_params
            if current_peer_params and "publickey" in current_peer_params:
                allowed_lines = current_peer_params.get("allowedips", ["0.0.0.0/0, ::/0"])
                allowed = [x.strip() for val in allowed_lines for x in val.split(",") if x.strip()]
                keepalive = int(current_peer_params["persistentkeepalive"][-1]) if "persistentkeepalive" in current_peer_params else None
                endpoint = current_peer_params.get("endpoint", [None])[-1]
                psk = current_peer_params.get("presharedkey", [None])[-1]
                peers.append(
                    WireGuardPeer(
                        public_key=current_peer_params["publickey"][-1],
                        endpoint=endpoint,
                        allowed_ips=allowed,
                        preshared_key=psk,
                        persistent_keepalive=keepalive,
                    )
                )
            current_peer_params = collections.defaultdict(list)

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[") and line.endswith("]"):
                sec_name = line[1:-1].strip().lower()
                if sec_name == "interface":
                    flush_peer()
                    current_section = "interface"
                elif sec_name == "peer":
                    flush_peer()
                    current_section = "peer"
                continue

            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip().lower()
                v = v.split("#")[0].strip()

                if current_section == "interface":
                    interface_params[k].append(v)
                elif current_section == "peer":
                    current_peer_params[k].append(v)

        flush_peer()

        if "privatekey" not in interface_params or not interface_params["privatekey"]:
            raise ValueError("WireGuard config missing PrivateKey in [Interface]")

        addrs = [x.strip() for val in interface_params.get("address", []) for x in val.split(",") if x.strip()]
        dns_lines = interface_params.get("dns", ["1.1.1.1"])
        dns = [x.strip() for val in dns_lines for x in val.split(",") if x.strip()]
        mtu = int(interface_params["mtu"][-1]) if "mtu" in interface_params else 1420
        port = int(interface_params["listenport"][-1]) if "listenport" in interface_params else None

        iface = WireGuardInterface(
            private_key=interface_params["privatekey"][-1],
            addresses=addrs,
            dns_servers=dns,
            mtu=mtu,
            listen_port=port,
        )
        return cls(name=name, interface=iface, peers=peers)

    def to_ini_string(self) -> str:
        out = ["[Interface]"]
        out.append(f"PrivateKey = {self.interface.private_key}")
        if self.interface.addresses:
            out.append(f"Address = {', '.join(self.interface.addresses)}")
        if self.interface.dns_servers:
            out.append(f"DNS = {', '.join(self.interface.dns_servers)}")
        out.append(f"MTU = {self.interface.mtu}")
        if self.interface.listen_port:
            out.append(f"ListenPort = {self.interface.listen_port}")

        for peer in self.peers:
            out.append("\n[Peer]")
            out.append(f"PublicKey = {peer.public_key}")
            if peer.endpoint:
                out.append(f"Endpoint = {peer.endpoint}")
            if peer.allowed_ips:
                out.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")
            if peer.preshared_key:
                out.append(f"PresharedKey = {peer.preshared_key}")
            if peer.persistent_keepalive:
                out.append(f"PersistentKeepalive = {peer.persistent_keepalive}")

        return "\n".join(out)

    @classmethod
    def create_cloudflare_warp_config(
        cls,
        private_key: Optional[str] = None,
        client_ipv4: str = "172.16.0.2/32",
        client_ipv6: str = "2606:4700:110:8f81:857e:8b9a:b042:d72b/128",
        endpoint: str = "162.159.192.1:2408",
        persistent_keepalive: int = 25,
        name: str = "Cloudflare-WARP",
    ) -> WireGuardConfig:
        """Factory method to generate a ready-to-use Cloudflare WARP WireGuard profile."""
        import secrets

        if not private_key:
            private_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")

        # Standard Cloudflare WARP gateway public key
        warp_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        iface = WireGuardInterface(
            private_key=private_key,
            addresses=[client_ipv4, client_ipv6],
            dns_servers=["1.1.1.1", "2606:4700:4700::1111"],
            mtu=1280,
        )
        peer = WireGuardPeer(
            public_key=warp_public_key,
            endpoint=endpoint,
            allowed_ips=["0.0.0.0/0", "::/0"],
            persistent_keepalive=persistent_keepalive,
        )
        return cls(name=name, interface=iface, peers=[peer])

    @classmethod
    def create_streaming_unblock_profile(
        cls,
        name: str,
        private_key: str,
        peer_public_key: str,
        endpoint: str,
        client_address: str = "10.0.0.2/32",
        allowed_ips: Optional[List[str]] = None,
        dns_servers: Optional[List[str]] = None,
        persistent_keepalive: int = 25,
    ) -> WireGuardConfig:
        """Creates a streaming geo-unblock WireGuard tunnel profile."""
        iface = WireGuardInterface(
            private_key=private_key,
            addresses=[client_address],
            dns_servers=dns_servers or ["1.1.1.1", "94.140.15.15"],
            mtu=1420,
        )
        peer = WireGuardPeer(
            public_key=peer_public_key,
            endpoint=endpoint,
            allowed_ips=allowed_ips or ["0.0.0.0/0", "::/0"],
            persistent_keepalive=persistent_keepalive,
        )
        return cls(name=name, interface=iface, peers=[peer])
