"""
RFC 1035 Compliant DNS Packet Parser and Serializer for AegisDNS / RethinkCore.
Zero-dependency, high-performance wire format decoding and encoding.
"""

from __future__ import annotations
import struct
import socket
from typing import List, Tuple, Optional


class RecordType:
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    OPT = 41
    HTTPS = 65
    ANY = 255

    @classmethod
    def to_string(cls, rtype: int) -> str:
        names = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            41: "OPT",
            65: "HTTPS",
            255: "ANY",
        }
        return names.get(rtype, f"TYPE{rtype}")


class RCode:
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


class DNSHeader:
    def __init__(
        self,
        id: int = 0,
        qr: int = 0,
        opcode: int = 0,
        aa: int = 0,
        tc: int = 0,
        rd: int = 1,
        ra: int = 0,
        rcode: int = 0,
        qdcount: int = 0,
        ancount: int = 0,
        nscount: int = 0,
        arcount: int = 0,
    ):
        self.id = id & 0xFFFF
        self.qr = qr & 1
        self.opcode = opcode & 0xF
        self.aa = aa & 1
        self.tc = tc & 1
        self.rd = rd & 1
        self.ra = ra & 1
        self.rcode = rcode & 0xF
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def to_bytes(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.rcode & 0xF)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple[DNSHeader, int]:
        if len(data) - offset < 12:
            raise ValueError(f"Packet too short for DNS header: {len(data) - offset} bytes")
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, offset)
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        rcode = flags & 0xF
        return (
            cls(id, qr, opcode, aa, tc, rd, ra, rcode, qdcount, ancount, nscount, arcount),
            offset + 12,
        )


def encode_dns_name(name: str) -> bytes:
    """Encodes a domain name (e.g. 'example.com') to DNS wire label format."""
    if not name or name == ".":
        return b"\x00"
    name = name.rstrip(".")
    parts = name.split(".")
    res = bytearray()
    for part in parts:
        bpart = part.encode("ascii", errors="replace")
        if len(bpart) > 63:
            raise ValueError(f"DNS label too long (>63 bytes): {part}")
        res.append(len(bpart))
        res.extend(bpart)
    res.append(0)
    return bytes(res)


def decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decodes a DNS name handling compression pointers (RFC 1035)."""
    labels = []
    jumped = False
    return_offset = offset
    visited_pointers = set()

    while True:
        if offset >= len(data):
            raise ValueError("Truncated DNS name in packet")
        length = data[offset]

        if length == 0:
            if not jumped:
                return_offset = offset + 1
            break

        # Check label type bits (top 2 bits per RFC 1035 section 4.1.4)
        label_type = length & 0xC0
        if label_type == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited_pointers:
                raise ValueError("Pointer loop detected in DNS compression")
            visited_pointers.add(ptr)
            if not jumped:
                return_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        elif label_type != 0x00:
            raise ValueError(f"Invalid DNS label type/reserved bits: 0x{label_type:02x}")

        if length > 63:
            raise ValueError(f"DNS label length exceeds 63 octets: {length}")

        offset += 1
        if offset + length > len(data):
            raise ValueError("Label length exceeds packet boundary")
        label = data[offset : offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    domain = ".".join(labels)
    if domain:
        domain += "."
    return domain, return_offset


class DNSQuestion:
    def __init__(self, qname: str, qtype: int = RecordType.A, qclass: int = 1):
        self.qname = qname if qname.endswith(".") else f"{qname}."
        self.qtype = qtype
        self.qclass = qclass

    def to_bytes(self) -> bytes:
        return encode_dns_name(self.qname) + struct.pack("!HH", self.qtype, self.qclass)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> Tuple[DNSQuestion, int]:
        qname, offset = decode_dns_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Truncated DNS Question section")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        return cls(qname, qtype, qclass), offset + 4

    def clean_name(self) -> str:
        return self.qname.rstrip(".").lower()


class DNSRR:
    def __init__(
        self,
        name: str,
        rtype: int,
        rclass: int = 1,
        ttl: int = 300,
        rdata: bytes = b"",
        rdata_str: Optional[str] = None,
    ):
        self.name = name if name.endswith(".") else f"{name}."
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.rdata_str = rdata_str or self._parse_rdata_str()

    @classmethod
    def _parse_rdata_str_with_packet(
        cls,
        rtype: int,
        rdata: bytes,
        full_packet: Optional[bytes] = None,
        rdata_offset: int = 0,
    ) -> str:
        if rtype == RecordType.A and len(rdata) == 4:
            return socket.inet_ntoa(rdata)
        elif rtype == RecordType.AAAA and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (RecordType.CNAME, RecordType.NS, RecordType.PTR):
            if full_packet is not None and 0 <= rdata_offset < len(full_packet):
                try:
                    name, _ = decode_dns_name(full_packet, rdata_offset)
                    return name.rstrip(".")
                except Exception:
                    pass
            try:
                name, _ = decode_dns_name(rdata, 0)
                return name.rstrip(".")
            except Exception:
                return rdata.hex()
        elif rtype == RecordType.MX:
            if len(rdata) >= 3:
                preference = struct.unpack_from("!H", rdata, 0)[0]
                if full_packet is not None and 0 <= rdata_offset + 2 < len(full_packet):
                    try:
                        ex_name, _ = decode_dns_name(full_packet, rdata_offset + 2)
                        return f"{preference} {ex_name.rstrip('.')}"
                    except Exception:
                        pass
                try:
                    ex_name, _ = decode_dns_name(rdata, 2)
                    return f"{preference} {ex_name.rstrip('.')}"
                except Exception:
                    pass
            return rdata.hex()
        elif rtype == RecordType.TXT:
            chunks = []
            idx = 0
            while idx < len(rdata):
                chunk_len = rdata[idx]
                idx += 1
                chunks.append(rdata[idx : idx + chunk_len].decode("utf-8", errors="replace"))
                idx += chunk_len
            return "".join(chunks)
        elif rtype == RecordType.SOA:
            if full_packet is not None and 0 <= rdata_offset < len(full_packet):
                try:
                    mname, off = decode_dns_name(full_packet, rdata_offset)
                    rname, off = decode_dns_name(full_packet, off)
                    if off + 20 <= len(full_packet):
                        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", full_packet, off)
                        return f"{mname.rstrip('.')} {rname.rstrip('.')} {serial} {refresh} {retry} {expire} {minimum}"
                except Exception:
                    pass
            return rdata.hex()
        return rdata.hex()

    def _parse_rdata_str(self) -> str:
        return self._parse_rdata_str_with_packet(self.rtype, self.rdata)

    def to_bytes(self) -> bytes:
        wire_rdata = self.rdata
        if self.rtype in (RecordType.CNAME, RecordType.NS, RecordType.PTR) and self.rdata_str:
            # If rdata contains a compression pointer, normalize to self-contained label bytes
            if not wire_rdata or (wire_rdata[0] & 0xC0) == 0xC0:
                wire_rdata = encode_dns_name(self.rdata_str)
        elif self.rtype == RecordType.MX and self.rdata_str:
            if not wire_rdata or (len(wire_rdata) >= 3 and (wire_rdata[2] & 0xC0) == 0xC0):
                parts = self.rdata_str.split(None, 1)
                pref = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 10
                target = parts[1] if len(parts) > 1 else ""
                wire_rdata = struct.pack("!H", pref) + encode_dns_name(target)

        res = bytearray(encode_dns_name(self.name))
        res.extend(struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, len(wire_rdata)))
        res.extend(wire_rdata)
        return bytes(res)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> Tuple[DNSRR, int]:
        name, offset = decode_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Truncated Resource Record header")
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("Resource Record data exceeds packet length")
        rdata = data[offset : offset + rdlength]
        rdata_str = cls._parse_rdata_str_with_packet(rtype, rdata, full_packet=data, rdata_offset=offset)
        return cls(name, rtype, rclass, ttl, rdata, rdata_str=rdata_str), offset + rdlength


class DNSPacket:
    def __init__(self, header: Optional[DNSHeader] = None):
        self.header = header or DNSHeader()
        self.questions: List[DNSQuestion] = []
        self.answers: List[DNSRR] = []
        self.authorities: List[DNSRR] = []
        self.additionals: List[DNSRR] = []

    def to_bytes(self) -> bytes:
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)

        out = bytearray(self.header.to_bytes())
        for q in self.questions:
            out.extend(q.to_bytes())
        for a in self.answers:
            out.extend(a.to_bytes())
        for ns in self.authorities:
            out.extend(ns.to_bytes())
        for ar in self.additionals:
            out.extend(ar.to_bytes())
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> DNSPacket:
        pkt = cls()
        header, offset = DNSHeader.from_bytes(data, 0)
        pkt.header = header

        for _ in range(header.qdcount):
            q, offset = DNSQuestion.from_bytes(data, offset)
            pkt.questions.append(q)

        for _ in range(header.ancount):
            rr, offset = DNSRR.from_bytes(data, offset)
            pkt.answers.append(rr)

        for _ in range(header.nscount):
            rr, offset = DNSRR.from_bytes(data, offset)
            pkt.authorities.append(rr)

        for _ in range(header.arcount):
            rr, offset = DNSRR.from_bytes(data, offset)
            pkt.additionals.append(rr)

        return pkt

    def create_response(self, rcode: int = RCode.NOERROR) -> DNSPacket:
        resp = DNSPacket()
        resp.header = DNSHeader(
            id=self.header.id,
            qr=1,
            opcode=self.header.opcode,
            aa=1,
            tc=0,
            rd=self.header.rd,
            ra=1,
            rcode=rcode,
        )
        resp.questions = list(self.questions)
        return resp

    def add_a_record(self, name: str, ip: str, ttl: int = 300) -> None:
        raw_ip = socket.inet_aton(ip)
        self.answers.append(DNSRR(name=name, rtype=RecordType.A, ttl=ttl, rdata=raw_ip, rdata_str=ip))

    def add_aaaa_record(self, name: str, ipv6: str, ttl: int = 300) -> None:
        raw_ip = socket.inet_pton(socket.AF_INET6, ipv6)
        self.answers.append(DNSRR(name=name, rtype=RecordType.AAAA, ttl=ttl, rdata=raw_ip, rdata_str=ipv6))

    def add_cname_record(self, name: str, target: str, ttl: int = 300) -> None:
        raw_target = encode_dns_name(target)
        self.answers.append(DNSRR(name=name, rtype=RecordType.CNAME, ttl=ttl, rdata=raw_target, rdata_str=target))

    def add_ptr_record(self, name: str, target: str, ttl: int = 300) -> None:
        raw_target = encode_dns_name(target)
        self.answers.append(DNSRR(name=name, rtype=RecordType.PTR, ttl=ttl, rdata=raw_target, rdata_str=target))

    def add_txt_record(self, name: str, text: str, ttl: int = 300) -> None:
        btext = text.encode("utf-8")
        raw_data = bytearray()
        for i in range(0, len(btext), 255):
            chunk = btext[i : i + 255]
            raw_data.append(len(chunk))
            raw_data.extend(chunk)
        self.answers.append(DNSRR(name=name, rtype=RecordType.TXT, ttl=ttl, rdata=bytes(raw_data), rdata_str=text))

    def add_mx_record(self, name: str, preference: int, exchange: str, ttl: int = 300) -> None:
        raw_data = struct.pack("!H", preference) + encode_dns_name(exchange)
        self.answers.append(DNSRR(name=name, rtype=RecordType.MX, ttl=ttl, rdata=raw_data, rdata_str=f"{preference} {exchange}"))

    def add_blocked_response(
        self,
        name: str,
        qtype: int = RecordType.A,
        ttl: int = 60,
        block_ip: str = "0.0.0.0",
        block_ipv6: str = "::",
    ) -> None:
        if qtype in (RecordType.A, RecordType.ANY):
            self.add_a_record(name=name, ip=block_ip, ttl=ttl)
        elif qtype == RecordType.AAAA:
            self.add_aaaa_record(name=name, ipv6=block_ipv6, ttl=ttl)
        # Non-IP queries (TXT, MX, SRV, HTTPS, etc.) receive NOERROR with 0 answers (NODATA)
