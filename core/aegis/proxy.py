"""
SOCKS5 and HTTP CONNECT Proxy Client and Manager for AegisDNS / RethinkCore.
Provides proxy endpoint validation, SOCKS5 client negotiation, and routing rules.
"""

from __future__ import annotations
import socket
import struct
from typing import Optional, Tuple, Dict, List


class ProxyType:
    SOCKS5 = "SOCKS5"
    HTTP = "HTTP"
    HTTPS = "HTTPS"


class ProxyEndpoint:
    def __init__(
        self,
        name: str,
        proxy_type: str = ProxyType.SOCKS5,
        host: str = "127.0.0.1",
        port: int = 1080,
        username: Optional[str] = None,
        password: Optional[str] = None,
        is_default: bool = False,
    ):
        self.name = name
        self.proxy_type = proxy_type.upper()
        self.host = host.strip()
        self.port = port
        self.username = username
        self.password = password
        self.is_default = is_default

    def validate(self) -> Tuple[bool, Optional[str]]:
        if not (1 <= self.port <= 65535):
            return False, f"Invalid port: {self.port}"
        if not self.host:
            return False, "Empty proxy host"
        if self.proxy_type not in (ProxyType.SOCKS5, ProxyType.HTTP, ProxyType.HTTPS):
            return False, f"Unsupported proxy type: {self.proxy_type}"
        return True, None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.proxy_type,
            "host": self.host,
            "port": self.port,
            "has_auth": bool(self.username),
            "is_default": self.is_default,
        }


class SOCKS5Client:
    """Implements RFC 1928 SOCKS5 client handshake for testing and proxy dispatch."""

    @staticmethod
    def build_handshake(username: Optional[str] = None, password: Optional[str] = None) -> bytes:
        if username and password:
            return b"\x05\x02\x00\x02"  # Version 5, 2 auth methods (No auth, User/Pass)
        return b"\x05\x01\x00"  # Version 5, 1 auth method (No auth)

    @staticmethod
    def build_auth_payload(username: str, password: str) -> bytes:
        u_bytes = username.encode("utf-8")
        p_bytes = password.encode("utf-8")
        out = bytearray([0x01, len(u_bytes)])
        out.extend(u_bytes)
        out.append(len(p_bytes))
        out.extend(p_bytes)
        return bytes(out)

    @staticmethod
    def build_connect_request(dst_host: str, dst_port: int) -> bytes:
        out = bytearray([0x05, 0x01, 0x00])  # SOCKS5, CONNECT, RSV
        # 1. Check if IPv4 (ATYP 0x01)
        try:
            raw_ip = socket.inet_aton(dst_host)
            out.append(0x01)
            out.extend(raw_ip)
            out.extend(struct.pack("!H", dst_port))
            return bytes(out)
        except OSError:
            pass

        # 2. Check if IPv6 (ATYP 0x04)
        clean_ip6 = dst_host.strip("[]")
        try:
            raw_ip6 = socket.inet_pton(socket.AF_INET6, clean_ip6)
            out.append(0x04)
            out.extend(raw_ip6)
            out.extend(struct.pack("!H", dst_port))
            return bytes(out)
        except OSError:
            pass

        # 3. Domain name (ATYP 0x03)
        bdomain = dst_host.encode("ascii", errors="replace")
        if len(bdomain) > 255:
            raise ValueError(f"Domain name exceeds 255 bytes: {dst_host}")
        out.append(0x03)
        out.append(len(bdomain))
        out.extend(bdomain)
        out.extend(struct.pack("!H", dst_port))
        return bytes(out)


class ProxyManager:
    def __init__(self):
        self.proxies: Dict[str, ProxyEndpoint] = {}
        self.domain_proxy_map: Dict[str, str] = {}  # domain -> proxy_name

    def add_proxy(self, proxy: ProxyEndpoint) -> Tuple[bool, Optional[str]]:
        ok, err = proxy.validate()
        if not ok:
            return False, err
        if proxy.is_default:
            for p in self.proxies.values():
                p.is_default = False
        self.proxies[proxy.name] = proxy
        return True, None

    def remove_proxy(self, name: str) -> bool:
        return bool(self.proxies.pop(name, None))

    def get_proxy(self, name: str) -> Optional[ProxyEndpoint]:
        return self.proxies.get(name)

    def get_default_proxy(self) -> Optional[ProxyEndpoint]:
        for p in self.proxies.values():
            if p.is_default:
                return p
        return None

    def set_domain_proxy(self, domain: str, proxy_name: str):
        self.domain_proxy_map[domain.rstrip(".").lower()] = proxy_name

    def route_target(self, domain: Optional[str] = None) -> Optional[ProxyEndpoint]:
        if domain:
            norm = domain.rstrip(".").lower()
            proxy_name = self.domain_proxy_map.get(norm)
            if proxy_name and proxy_name in self.proxies:
                return self.proxies[proxy_name]
        return self.get_default_proxy()

    def list_proxies(self) -> List[dict]:
        return [p.to_dict() for p in self.proxies.values()]
