"""
WireGuard Configuration Parser, Validator, and Manager for AegisDNS / RethinkCore.
Handles standard WireGuard INI config syntax, pure-Python RFC 7748 Curve25519 key generation,
Cloudflare WARP live registration (with ClientID + warp_enabled activation),
AllowedIPs CIDR verification, and multi-peer profiles.
"""

from __future__ import annotations
import base64
import collections
import datetime
import ipaddress
import json
import secrets
import urllib.request
from typing import List, Optional, Dict, Tuple, Any


# --- Pure-Python RFC 7748 X25519 (zero external dependencies) ---
_X25519_P = (1 << 255) - 19
_X25519_A24 = 121665
_X25519_BASEPOINT = (9).to_bytes(32, "little")


def _cswap(swap: int, x_2: int, x_3: int) -> Tuple[int, int]:
    dummy = swap * (x_2 ^ x_3)
    return x_2 ^ dummy, x_3 ^ dummy


def _x25519_scalar_mult(scalar_bytes: bytes, u_bytes: bytes = _X25519_BASEPOINT) -> bytes:
    """RFC 7748 Section 5 X25519 Montgomery ladder scalar multiplication."""
    if len(scalar_bytes) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be exactly 32 bytes")
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")

    u_arr = bytearray(u_bytes)
    u_arr[31] &= 127
    u = int.from_bytes(u_arr, "little") % _X25519_P

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t

        a = (x_2 + z_2) % _X25519_P
        aa = (a * a) % _X25519_P
        b = (x_2 - z_2) % _X25519_P
        bb = (b * b) % _X25519_P
        e = (aa - bb) % _X25519_P
        c = (x_3 + z_3) % _X25519_P
        d = (x_3 - z_3) % _X25519_P
        da = (d * a) % _X25519_P
        cb = (c * b) % _X25519_P
        x_3 = pow(da + cb, 2, _X25519_P)
        z_3 = (x_1 * pow(da - cb, 2, _X25519_P)) % _X25519_P
        x_2 = (aa * bb) % _X25519_P
        z_2 = (e * (aa + _X25519_A24 * e)) % _X25519_P

    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    res = (x_2 * pow(z_2, _X25519_P - 2, _X25519_P)) % _X25519_P
    return res.to_bytes(32, "little")


def derive_public_key(private_key_b64: str) -> str:
    """Derives the WireGuard Curve25519 public key (Base64) from a Base64 private key."""
    if not is_valid_base64_key(private_key_b64):
        raise ValueError("Invalid WireGuard Base64 private key")
    raw_priv = base64.b64decode(private_key_b64.strip(), validate=True)
    raw_pub = _x25519_scalar_mult(raw_priv, _X25519_BASEPOINT)
    return base64.b64encode(raw_pub).decode("ascii")


def generate_keypair() -> Tuple[str, str]:
    """Generates a cryptographically valid WireGuard (private_key_b64, public_key_b64) pair."""
    raw_priv = bytearray(secrets.token_bytes(32))
    raw_priv[0] &= 248
    raw_priv[31] &= 127
    raw_priv[31] |= 64
    priv_b64 = base64.b64encode(bytes(raw_priv)).decode("ascii")
    pub_b64 = derive_public_key(priv_b64)
    return priv_b64, pub_b64


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


def is_valid_client_id(client_id: str) -> bool:
    """Cloudflare WARP ClientID is 3 reserved bytes encoded in Base64 (4 chars)."""
    cid = client_id.strip()
    if not cid:
        return False
    try:
        raw = base64.b64decode(cid, validate=True)
        return len(raw) == 3
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
        self.allowed_ips: List[str] = allowed_ips if allowed_ips is not None else ["0.0.0.0/0", "::/0"]
        self.preshared_key = preshared_key.strip() if preshared_key else None
        self.persistent_keepalive = persistent_keepalive

    def validate(self) -> List[str]:
        errors = []
        if not is_valid_base64_key(self.public_key):
            errors.append(f"Invalid PublicKey format: '{self.public_key}'")

        if self.preshared_key and not is_valid_base64_key(self.preshared_key):
            errors.append(f"Invalid PresharedKey format: '{self.preshared_key}'")

        if self.persistent_keepalive is not None and not (0 <= self.persistent_keepalive <= 65535):
            errors.append(f"Invalid PersistentKeepalive: {self.persistent_keepalive}")

        if self.endpoint:
            ep = self.endpoint.strip()
            if ep.startswith("["):
                end_b = ep.find("]")
                if end_b <= 1 or not ep[end_b + 1 :].startswith(":"):
                    errors.append(
                        f"Invalid bracketed IPv6 endpoint format: '{self.endpoint}', expected [host]:port"
                    )
                else:
                    host_part = ep[1:end_b]
                    try:
                        ipaddress.IPv6Address(host_part)
                    except ValueError:
                        errors.append(f"Invalid IPv6 address in Endpoint: '{host_part}'")
                    try:
                        port = int(ep[end_b + 2 :])
                        if not (1 <= port <= 65535):
                            errors.append(f"Invalid Endpoint port: {port}")
                    except ValueError:
                        errors.append(f"Invalid Endpoint port in '{self.endpoint}'")
            else:
                parts = ep.rsplit(":", 1)
                if len(parts) != 2 or not parts[0].strip():
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
        client_id: Optional[str] = None,
    ):
        self.private_key = private_key.strip()
        self.addresses: List[str] = addresses or []
        self.dns_servers: List[str] = dns_servers or ["1.1.1.1"]
        self.mtu = mtu
        self.listen_port = listen_port
        self.client_id = client_id.strip() if client_id else None

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

        if self.listen_port is not None and not (1 <= self.listen_port <= 65535):
            errors.append(f"Invalid ListenPort: {self.listen_port}")

        if self.client_id is not None and not is_valid_client_id(self.client_id):
            errors.append(f"Invalid WARP ClientID (expected 3-byte Base64): '{self.client_id}'")

        return errors

    def to_dict(self) -> dict:
        data: Dict[str, Any] = {
            "addresses": self.addresses,
            "dns_servers": self.dns_servers,
            "mtu": self.mtu,
            "listen_port": self.listen_port,
        }
        if self.client_id:
            data["client_id"] = self.client_id
        return data


class WireGuardConfig:
    def __init__(
        self,
        name: str,
        interface: WireGuardInterface,
        peers: Optional[List[WireGuardPeer]] = None,
        is_registered: bool = False,
    ):
        self.name = name
        self.interface = interface
        self.peers = peers or []
        self.is_registered = is_registered

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

        def parse_int_field(raw: str, field_name: str) -> int:
            try:
                return int(raw)
            except ValueError as exc:
                raise ValueError(f"Invalid integer for {field_name}: '{raw}'") from exc

        def flush_peer():
            nonlocal current_peer_params
            if current_peer_params and "publickey" in current_peer_params:
                allowed_lines = current_peer_params.get("allowedips", ["0.0.0.0/0, ::/0"])
                allowed = [x.strip() for val in allowed_lines for x in val.split(",") if x.strip()]
                keepalive = (
                    parse_int_field(current_peer_params["persistentkeepalive"][-1], "PersistentKeepalive")
                    if "persistentkeepalive" in current_peer_params
                    else None
                )
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
        mtu = parse_int_field(interface_params["mtu"][-1], "MTU") if "mtu" in interface_params else 1420
        port = (
            parse_int_field(interface_params["listenport"][-1], "ListenPort")
            if "listenport" in interface_params
            else None
        )
        client_id = interface_params.get("clientid", [None])[-1]

        iface = WireGuardInterface(
            private_key=interface_params["privatekey"][-1],
            addresses=addrs,
            dns_servers=dns,
            mtu=mtu,
            listen_port=port,
            client_id=client_id,
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
        if self.interface.client_id:
            out.append(f"ClientID = {self.interface.client_id}")

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
        client_id: Optional[str] = None,
    ) -> WireGuardConfig:
        """Factory method to generate a Cloudflare WARP WireGuard profile template."""
        if not private_key:
            private_key, _ = generate_keypair()

        # Standard Cloudflare WARP gateway public key
        warp_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        iface = WireGuardInterface(
            private_key=private_key,
            addresses=[client_ipv4, client_ipv6],
            dns_servers=["1.1.1.1", "2606:4700:4700::1111"],
            mtu=1280,
            client_id=client_id,
        )
        peer = WireGuardPeer(
            public_key=warp_public_key,
            endpoint=endpoint,
            allowed_ips=["0.0.0.0/0", "::/0"],
            persistent_keepalive=persistent_keepalive,
        )
        return cls(name=name, interface=iface, peers=[peer], is_registered=False)

    @staticmethod
    def _resolve_warp_endpoint(ep: Dict[str, Any], default_endpoint: str) -> str:
        """Picks a direct IPv4:port endpoint from Cloudflare WARP API response to avoid DNS deadlock."""
        ports = ep.get("ports") or [2408]
        port = ports[0] if ports and isinstance(ports[0], int) and 1 <= ports[0] <= 65535 else 2408
        v4 = ep.get("v4")
        if isinstance(v4, str) and v4.strip():
            host_only = v4.rsplit(":", 1)[0] if ":" in v4 else v4
            try:
                ipaddress.IPv4Address(host_only)
                return f"{host_only}:{port}"
            except ValueError:
                pass
        host = ep.get("host")
        if isinstance(host, str) and host.strip():
            return host.strip()
        return default_endpoint

    @classmethod
    def register_cloudflare_warp(
        cls,
        name: str = "Cloudflare-WARP",
        endpoint_override: Optional[str] = None,
        timeout: float = 8.0,
        locale: str = "en_US",
        dns_servers: Optional[List[str]] = None,
        allow_fallback: bool = True,
    ) -> WireGuardConfig:
        """
        Dynamically registers a new RFC 7748 Curve25519 client with Cloudflare WARP API
        (api.cloudflareclient.com), activates warp_enabled via PATCH, and captures ClientID.
        If allow_fallback=False, raises RuntimeError instead of returning an unregistered profile.
        """
        # Always derive a true Curve25519 public key (never leak the private key!)
        private_key, client_pub = generate_keypair()

        client_ipv4 = "172.16.0.2/32"
        client_ipv6 = "2606:4700:110:8f81:857e:8b9a:b042:d72b/128"
        endpoint = endpoint_override or "162.159.192.1:2408"
        warp_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        client_id: Optional[str] = None
        registered = False

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        payload = {
            "key": client_pub,
            "install_id": "",
            "fcm_token": "",
            "tos": now_str,
            "model": "PC",
            "type": "Android",
            "locale": locale,
        }
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "User-Agent": "okhttp/3.12.1",
            "CF-Client-Version": "a-6.11-2223",
        }
        reg_url = "https://api.cloudflareclient.com/v0a2158/reg"
        req = urllib.request.Request(
            reg_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                reg_id = res.get("id", "")
                token = res.get("token", "")
                cfg_data = res.get("config", {})

                cid = cfg_data.get("client_id")
                if isinstance(cid, str) and is_valid_client_id(cid):
                    client_id = cid

                ifaces = cfg_data.get("interface", {}).get("addresses", {})
                if ifaces.get("v4"):
                    client_ipv4 = f"{ifaces['v4']}/32"
                if ifaces.get("v6"):
                    client_ipv6 = f"{ifaces['v6']}/128"

                peers_list = cfg_data.get("peers", [])
                if peers_list:
                    p0 = peers_list[0]
                    if p0.get("public_key"):
                        warp_public_key = p0["public_key"]
                    ep = p0.get("endpoint", {})
                    if not endpoint_override and isinstance(ep, dict):
                        endpoint = cls._resolve_warp_endpoint(ep, endpoint)

                # Activate WARP routing via PATCH /reg/{id}
                if reg_id and token:
                    patch_headers = dict(headers)
                    patch_headers["Authorization"] = f"Bearer {token}"
                    patch_req = urllib.request.Request(
                        f"{reg_url}/{reg_id}",
                        data=json.dumps({"warp_enabled": True}).encode("utf-8"),
                        headers=patch_headers,
                        method="PATCH",
                    )
                    with urllib.request.urlopen(patch_req, timeout=timeout) as patch_resp:
                        patch_body = json.loads(patch_resp.read().decode("utf-8"))
                        if not patch_body.get("warp_enabled", False):
                            raise RuntimeError("Cloudflare WARP PATCH did not confirm warp_enabled=true")
                registered = True
        except Exception as exc:
            if not allow_fallback:
                raise RuntimeError(f"Cloudflare WARP live registration failed: {exc}") from exc

        iface = WireGuardInterface(
            private_key=private_key,
            addresses=[client_ipv4, client_ipv6],
            dns_servers=dns_servers or ["1.1.1.1", "2606:4700:4700::1111"],
            mtu=1280,
            client_id=client_id,
        )
        peer = WireGuardPeer(
            public_key=warp_public_key,
            endpoint=endpoint,
            allowed_ips=["0.0.0.0/0", "::/0"],
            persistent_keepalive=25,
        )
        return cls(name=name, interface=iface, peers=[peer], is_registered=registered)

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

    @classmethod
    def get_available_locations(cls) -> List[Dict[str, Any]]:
        """Returns the list of preset location profiles supported by Aegis."""
        return [dict(p) for p in LOCATION_PRESETS]

    @classmethod
    def get_location_preset(cls, code: str) -> Optional[Dict[str, Any]]:
        """Lookup location preset by country code (case-insensitive)."""
        code = code.strip().upper()
        for p in LOCATION_PRESETS:
            if p["code"] == code:
                return dict(p)
        return None

    @classmethod
    def create_location_profile(
        cls,
        country_code: str,
        name: Optional[str] = None,
        private_key: Optional[str] = None,
        peer_public_key: Optional[str] = None,
        client_address: str = "172.16.0.2/32",
        mtu: int = 1280,
        register_live: bool = False,
        allow_fallback: bool = True,
    ) -> WireGuardConfig:
        """
        Creates a location-wise WireGuard profile for the specified country.
        When register_live=True, performs live Cloudflare WARP registration (with ClientID + PATCH).
        Raises ValueError if the country code is unknown.
        """
        preset = cls.get_location_preset(country_code)
        if not preset:
            raise ValueError(f"Unknown location country code: {country_code}")

        prof_name = name or f"{preset['flag']} {preset['name']} ({preset['city']})"

        if register_live:
            return cls.register_cloudflare_warp(
                name=prof_name,
                locale=f"en_{preset['code']}",
                dns_servers=list(preset.get("dns", ["1.1.1.1", "94.140.15.15"])),
                allow_fallback=allow_fallback,
            )

        if not private_key:
            private_key, _ = generate_keypair()

        peer_pub = peer_public_key or "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        iface = WireGuardInterface(
            private_key=private_key,
            addresses=[client_address, "2606:4700:110:8f81:857e:8b9a:b042:d72b/128"],
            dns_servers=list(preset.get("dns", ["1.1.1.1", "94.140.15.15"])),
            mtu=mtu,
        )
        peer = WireGuardPeer(
            public_key=peer_pub,
            endpoint=preset["endpoint"],
            allowed_ips=["0.0.0.0/0", "::/0"],
            persistent_keepalive=25,
        )
        return cls(name=prof_name, interface=iface, peers=[peer], is_registered=False)


LOCATION_PRESETS: List[Dict[str, Any]] = [
    {
        "code": "US",
        "name": "United States",
        "city": "Ashburn, VA",
        "flag": "🇺🇸",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "GB",
        "name": "United Kingdom",
        "city": "London",
        "flag": "🇬🇧",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "DE",
        "name": "Germany",
        "city": "Frankfurt",
        "flag": "🇩🇪",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "JP",
        "name": "Japan",
        "city": "Tokyo",
        "flag": "🇯🇵",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "SG",
        "name": "Singapore",
        "city": "Singapore",
        "flag": "🇸🇬",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "CA",
        "name": "Canada",
        "city": "Toronto",
        "flag": "🇨🇦",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "NL",
        "name": "Netherlands",
        "city": "Amsterdam",
        "flag": "🇳🇱",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "IN",
        "name": "India",
        "city": "Mumbai",
        "flag": "🇮🇳",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "FR",
        "name": "France",
        "city": "Paris",
        "flag": "🇫🇷",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "AU",
        "name": "Australia",
        "city": "Sydney",
        "flag": "🇦🇺",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "CH",
        "name": "Switzerland",
        "city": "Zurich",
        "flag": "🇨🇭",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
    {
        "code": "BR",
        "name": "Brazil",
        "city": "São Paulo",
        "flag": "🇧🇷",
        "endpoint": "162.159.192.1:2408",
        "dns": ["1.1.1.1", "94.140.15.15"],
    },
]
