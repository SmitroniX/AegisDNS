import unittest
import struct
from aegis.dns_packet import (
    DNSPacket,
    DNSHeader,
    DNSQuestion,
    DNSRR,
    RecordType,
    RCode,
    encode_dns_name,
    decode_dns_name,
)


class TestDNSPacket(unittest.TestCase):
    def test_encode_decode_dns_name(self):
        encoded = encode_dns_name("example.com")
        self.assertEqual(encoded, b"\x07example\x03com\x00")

        decoded, offset = decode_dns_name(encoded, 0)
        self.assertEqual(decoded, "example.com.")
        self.assertEqual(offset, len(encoded))

    def test_header_serialization_roundtrip(self):
        hdr = DNSHeader(
            id=0x1234,
            qr=1,
            opcode=0,
            aa=1,
            tc=0,
            rd=1,
            ra=1,
            rcode=RCode.NOERROR,
            qdcount=1,
            ancount=2,
            nscount=0,
            arcount=0,
        )
        b = hdr.to_bytes()
        self.assertEqual(len(b), 12)

        hdr2, off = DNSHeader.from_bytes(b, 0)
        self.assertEqual(off, 12)
        self.assertEqual(hdr2.id, 0x1234)
        self.assertEqual(hdr2.qr, 1)
        self.assertEqual(hdr2.aa, 1)
        self.assertEqual(hdr2.rd, 1)
        self.assertEqual(hdr2.ra, 1)
        self.assertEqual(hdr2.rcode, RCode.NOERROR)
        self.assertEqual(hdr2.qdcount, 1)
        self.assertEqual(hdr2.ancount, 2)

    def test_question_serialization(self):
        q = DNSQuestion(qname="google.com", qtype=RecordType.A, qclass=1)
        b = q.to_bytes()
        q2, off = DNSQuestion.from_bytes(b, 0)
        self.assertEqual(q2.clean_name(), "google.com")
        self.assertEqual(q2.qtype, RecordType.A)
        self.assertEqual(q2.qclass, 1)

    def test_packet_with_a_and_aaaa_answers(self):
        pkt = DNSPacket()
        pkt.header.id = 42
        pkt.questions.append(DNSQuestion(qname="test.org", qtype=RecordType.A))
        pkt.add_a_record("test.org", "93.184.216.34", ttl=120)
        pkt.add_aaaa_record("test.org", "2606:2800:220:1:248:1893:25c8:1946", ttl=240)

        wire = pkt.to_bytes()
        parsed = DNSPacket.from_bytes(wire)

        self.assertEqual(parsed.header.id, 42)
        self.assertEqual(len(parsed.questions), 1)
        self.assertEqual(parsed.questions[0].clean_name(), "test.org")
        self.assertEqual(len(parsed.answers), 2)
        self.assertEqual(parsed.answers[0].rdata_str, "93.184.216.34")
        self.assertEqual(parsed.answers[0].ttl, 120)
        self.assertEqual(parsed.answers[1].rdata_str, "2606:2800:220:1:248:1893:25c8:1946")
        self.assertEqual(parsed.answers[1].ttl, 240)

    def test_pointer_loop_protection(self):
        # Craft a malicious payload with pointer loop (offset 0 points to offset 0)
        loop_data = b"\xc0\x00"
        with self.assertRaises(ValueError):
            decode_dns_name(loop_data, 0)

    def test_truncated_header_fails(self):
        with self.assertRaises(ValueError):
            DNSHeader.from_bytes(b"\x00\x01\x02", 0)

    def test_cname_compression_pointer_resolution(self):
        # Header (12 bytes) + Question "cdn.example.com" (17 bytes + 4 bytes = 21 bytes)
        # Offset 12: 03 "cdn" 07 "example" 03 "com" 00
        # Offset 16 is "example.com"
        hdr = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        q_bytes = b"\x03cdn\x07example\x03com\x00\x00\x05\x00\x01"
        # Answer: name pointer to offset 12 (0xc0 0x0c), TYPE CNAME (5), CLASS 1, TTL 300, RDLENGTH 2, RDATA pointer to offset 16 (0xc0 0x10)
        ans_bytes = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x2c\x00\x02\xc0\x10"
        raw_pkt = hdr + q_bytes + ans_bytes

        pkt = DNSPacket.from_bytes(raw_pkt)
        self.assertEqual(len(pkt.answers), 1)
        self.assertEqual(pkt.answers[0].rtype, RecordType.CNAME)
        self.assertEqual(pkt.answers[0].rdata_str, "example.com")

        # Serialized packet can be read without crashing and retains the CNAME target
        wire = pkt.to_bytes()
        pkt2 = DNSPacket.from_bytes(wire)
        self.assertEqual(pkt2.answers[0].rdata_str, "example.com")

    def test_txt_and_mx_records(self):
        pkt = DNSPacket()
        pkt.add_txt_record("example.com", "v=spf1 include:_spf.google.com ~all")
        pkt.add_mx_record("example.com", 10, "mail.example.com")

        wire = pkt.to_bytes()
        parsed = DNSPacket.from_bytes(wire)
        self.assertEqual(len(parsed.answers), 2)
        self.assertEqual(parsed.answers[0].rtype, RecordType.TXT)
        self.assertEqual(parsed.answers[0].rdata_str, "v=spf1 include:_spf.google.com ~all")
        self.assertEqual(parsed.answers[1].rtype, RecordType.MX)
        self.assertEqual(parsed.answers[1].rdata_str, "10 mail.example.com")

    def test_rfc1035_reserved_label_bits_rejected(self):
        # 0x41 has top bits 01 (reserved)
        data = b"\x41" + b"a" * 65 + b"\x00"
        with self.assertRaises(ValueError):
            decode_dns_name(data, 0)


if __name__ == "__main__":
    unittest.main()
