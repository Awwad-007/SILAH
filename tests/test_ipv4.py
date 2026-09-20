"""Tests for IPv4 packet parsing, serialization, and Internet Checksum (protocol/ipv4.py)."""

import struct
import unittest
from pathlib import Path

from protocol.arp import ip_from_str, ip_to_str
from protocol.ipv4 import (
    IPV4_MIN_HEADER_LEN,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    IPv4Packet,
    checksum,
)


class TestIPv4(unittest.TestCase):
    """Unit tests for IPv4 protocol layer and RFC 1071 internet checksum."""

    def test_constants(self) -> None:
        """Verify IPv4 protocol numbers and header length constants."""
        self.assertEqual(IPV4_MIN_HEADER_LEN, 20)
        self.assertEqual(PROTO_ICMP, 0x01)
        self.assertEqual(PROTO_TCP, 0x06)
        self.assertEqual(PROTO_UDP, 0x11)

    def test_checksum_standard_vectors(self) -> None:
        """Verify RFC 1071 checksum calculation and self-validation property."""
        # Known IPv4 header with checksum zeroed:
        # 45 00 00 3c 1c 46 40 00 40 06 [00 00] ac 10 0a 63 ac 10 0a 0c
        raw_header_zero = bytes.fromhex("4500003c1c46400040060000ac100a63ac100a0c")
        chk = checksum(raw_header_zero)
        self.assertEqual(chk, 0xB1E6, "Checksum for test vector header must be 0xb1e6")

        # Self-validation: re-running checksum with the real checksum in place yields 0
        raw_header_valid = raw_header_zero[:10] + struct.pack("!H", chk) + raw_header_zero[12:]
        self.assertEqual(checksum(raw_header_valid), 0x0000, "Valid header checksum must evaluate to 0")

    def test_checksum_odd_length_padding(self) -> None:
        """Verify checksum pads odd-length byte buffers with trailing zero byte."""
        data_odd = b"\x01\x02\x03"
        # Padded to b"\x01\x02\x03\x00" -> words 0x0102 + 0x0300 = 0x0402 -> ~0x0402 & 0xFFFF = 0xFBFD
        self.assertEqual(checksum(data_odd), 0xFBFD)

    def test_checksum_carry_folding(self) -> None:
        """Verify 16-bit accumulator carry bits are properly folded back into lower 16 bits."""
        # Two 0xFFFF words sum to 0x1FFFE -> fold: 0xFFFE + 1 = 0xFFFF -> ~0xFFFF = 0x0000
        data = b"\xff\xff\xff\xff"
        self.assertEqual(checksum(data), 0x0000)

    def test_ipv4_packet_pack_and_parse_roundtrip(self) -> None:
        """Verify pack() and parse() round-trip for standard IPv4 packet."""
        src_ip = ip_from_str("10.0.0.1")
        dst_ip = ip_from_str("10.0.0.2")
        payload = b"TEST_IPV4_PAYLOAD_BYTES"

        pkt = IPv4Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=PROTO_ICMP,
            payload=payload,
            ttl=64,
            ident=0x1234,
            flags=2,  # Don't Fragment
            frag_offset=0,
            tos=0,
        )

        packed = pkt.pack()
        self.assertEqual(len(packed), 20 + len(payload))
        self.assertEqual(pkt.total_len, 20 + len(payload))

        # Checksum of the 20-byte header must validate to 0
        self.assertEqual(checksum(packed[:20]), 0)

        parsed = IPv4Packet.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.version, 4)
        self.assertEqual(parsed.ihl, 5)
        self.assertEqual(parsed.tos, 0)
        self.assertEqual(parsed.total_len, 20 + len(payload))
        self.assertEqual(parsed.ident, 0x1234)
        self.assertEqual(parsed.flags, 2)
        self.assertEqual(parsed.frag_offset, 0)
        self.assertEqual(parsed.ttl, 64)
        self.assertEqual(parsed.protocol, PROTO_ICMP)
        self.assertEqual(parsed.src_ip, src_ip)
        self.assertEqual(parsed.dst_ip, dst_ip)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.options, b"")

    def test_ipv4_options_handling(self) -> None:
        """Verify options parsing and packing (IHL > 5)."""
        src_ip = ip_from_str("192.168.1.10")
        dst_ip = ip_from_str("192.168.1.1")
        options = b"\x01\x01\x01\x01"  # 4 bytes of NOP options
        payload = b"OPTIONS_PAYLOAD"

        pkt = IPv4Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=PROTO_TCP,
            payload=payload,
            options=options,
        )

        packed = pkt.pack()
        # 20 base header + 4 options = 24 bytes header (IHL = 6)
        self.assertEqual(pkt.ihl, 6)
        self.assertEqual(len(packed), 24 + len(payload))

        # Checksum covers 24-byte header
        self.assertEqual(checksum(packed[:24]), 0)

        parsed = IPv4Packet.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.ihl, 6)
        self.assertEqual(parsed.options, options)
        self.assertEqual(parsed.payload, payload)

    def test_ipv4_malformed_and_corrupt_inputs(self) -> None:
        """Verify parse() returns None on truncated, malformed, or corrupted inputs."""
        # Truncated
        self.assertIsNone(IPv4Packet.parse(b""))
        self.assertIsNone(IPv4Packet.parse(b"\x45" * 19))

        # Valid packet as base
        valid = IPv4Packet(
            src_ip=ip_from_str("10.0.0.1"),
            dst_ip=ip_from_str("10.0.0.2"),
            protocol=PROTO_ICMP,
            payload=b"data",
        ).pack()

        # Wrong version (e.g. IPv6 = 6)
        wrong_ver = bytes([0x65]) + valid[1:]
        self.assertIsNone(IPv4Packet.parse(wrong_ver))

        # Invalid IHL (< 5)
        bad_ihl = bytes([0x44]) + valid[1:]
        self.assertIsNone(IPv4Packet.parse(bad_ihl))

        # Corrupted checksum (flip a bit)
        corrupted_chk = valid[:10] + bytes([valid[10] ^ 0xFF, valid[11]]) + valid[12:]
        self.assertIsNone(IPv4Packet.parse(corrupted_chk))

        # Truncated payload (total_len claims more than available bytes)
        truncated_payload = valid[:-2]
        self.assertIsNone(IPv4Packet.parse(truncated_payload))

    def test_ipv4_trailing_ethernet_padding_trimmed(self) -> None:
        """Verify trailing Ethernet minimum-frame padding is cleanly trimmed from payload."""
        payload = b"SHORT"
        pkt = IPv4Packet(
            src_ip=ip_from_str("10.0.0.1"),
            dst_ip=ip_from_str("10.0.0.2"),
            protocol=PROTO_ICMP,
            payload=payload,
        )
        packed = pkt.pack()  # 20 header + 5 payload = 25 bytes

        # Simulate Ethernet minimum payload padding (pad to 46 bytes)
        padded_raw = packed + (b"\x00" * 21)

        parsed = IPv4Packet.parse(padded_raw)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.total_len, 25)
        self.assertEqual(parsed.payload, payload, "Payload must not contain trailing padding bytes")

    def test_ipv4_repr(self) -> None:
        """Verify __repr__ contains readable IP addresses and protocol info."""
        pkt = IPv4Packet(
            src_ip=ip_from_str("10.0.0.1"),
            dst_ip=ip_from_str("10.0.0.2"),
            protocol=PROTO_ICMP,
            payload=b"ping",
        )
        r = repr(pkt)
        self.assertIn("10.0.0.1", r)
        self.assertIn("10.0.0.2", r)
        self.assertIn("proto=0x01", r)
        self.assertIn("ttl=64", r)

    def test_no_socket_references(self) -> None:
        """Verify protocol/ipv4.py has zero references to OS socket creation APIs."""
        content = (Path(__file__).resolve().parent.parent / "protocol" / "ipv4.py").read_text(encoding="utf-8")
        for token in ["socket.socket", "AF_INET", "SOCK_STREAM", "SOCK_DGRAM"]:
            self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
