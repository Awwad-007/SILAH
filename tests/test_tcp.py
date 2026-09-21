"""Tests for TCP Segment Parsing, Serialization, and Pseudo-Header Checksums (protocol/tcp.py)."""

import struct
import unittest
from pathlib import Path

from protocol.arp import ip_from_str
from protocol.ethernet import ETHERTYPE_IPV4, EthernetFrame, mac_from_str
from protocol.ipv4 import PROTO_TCP, IPv4Packet
from protocol.tcp import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    FLAG_URG,
    TCP_MIN_HEADER_LEN,
    TcpSegment,
    flags_to_str,
)


class TestTcp(unittest.TestCase):
    """Unit and integration tests for TCP protocol framing and pseudo-header checksums."""

    def test_constants_and_flags_to_str(self) -> None:
        """Verify TCP header constants, flag bit values, and flags_to_str formatting."""
        self.assertEqual(TCP_MIN_HEADER_LEN, 20)
        self.assertEqual(FLAG_FIN, 0x01)
        self.assertEqual(FLAG_SYN, 0x02)
        self.assertEqual(FLAG_RST, 0x04)
        self.assertEqual(FLAG_PSH, 0x08)
        self.assertEqual(FLAG_ACK, 0x10)
        self.assertEqual(FLAG_URG, 0x20)

        # Formatting in specified display order: SYN, ACK, FIN, RST, PSH, URG
        self.assertEqual(flags_to_str(0), "-")
        self.assertEqual(flags_to_str(FLAG_SYN), "SYN")
        self.assertEqual(flags_to_str(FLAG_SYN | FLAG_ACK), "SYN|ACK")
        self.assertEqual(flags_to_str(FLAG_FIN | FLAG_ACK | FLAG_PSH), "ACK|FIN|PSH")
        self.assertEqual(
            flags_to_str(FLAG_SYN | FLAG_ACK | FLAG_FIN | FLAG_RST | FLAG_PSH | FLAG_URG),
            "SYN|ACK|FIN|RST|PSH|URG",
        )

    def test_tcp_segment_pack_and_parse_roundtrip(self) -> None:
        """Verify pack() and parse() round-trip preserves all fields with default header."""
        src_ip = ip_from_str("10.0.0.1")
        dst_ip = ip_from_str("10.0.0.2")
        payload = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"

        seg = TcpSegment(
            src_port=54321,
            dst_port=80,
            seq=100000,
            ack=200000,
            flags=FLAG_PSH | FLAG_ACK,
            window=65535,
            payload=payload,
            urgent_ptr=0,
        )

        packed = seg.pack(src_ip, dst_ip)
        self.assertEqual(len(packed), 20 + len(payload))
        self.assertEqual(seg.data_offset, 5)

        parsed = TcpSegment.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.src_port, 54321)
        self.assertEqual(parsed.dst_port, 80)
        self.assertEqual(parsed.seq, 100000)
        self.assertEqual(parsed.ack, 200000)
        self.assertEqual(parsed.flags, FLAG_PSH | FLAG_ACK)
        self.assertEqual(parsed.window, 65535)
        self.assertEqual(parsed.data_offset, 5)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.options, b"")
        self.assertEqual(parsed.urgent_ptr, 0)
        self.assertEqual(parsed.checksum, seg.checksum)

    def test_independent_checksum_calculation(self) -> None:
        """Verify TCP checksum calculation against an independent from-scratch implementation in test."""
        src_ip = ip_from_str("192.168.1.100")
        dst_ip = ip_from_str("192.168.1.1")
        payload = b"INDEPENDENT_TEST_PAYLOAD"

        seg = TcpSegment(
            src_port=1234,
            dst_port=8080,
            seq=42,
            ack=99,
            flags=FLAG_SYN,
            window=8192,
            payload=payload,
        )

        packed = seg.pack(src_ip, dst_ip)

        # --- Independent from-scratch checksum calculation ---
        # 1. Construct 12-byte pseudo-header: src_ip, dst_ip, 0, protocol=6, tcp_length
        tcp_total_len = 20 + len(payload)
        pseudo_hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 6, tcp_total_len)

        # 2. Re-pack segment with checksum zeroed
        offset_flags = (5 << 12) | FLAG_SYN
        hdr_zero = struct.pack("!HHIIHHHH", 1234, 8080, 42, 99, offset_flags, 8192, 0, 0)
        full_buffer = pseudo_hdr + hdr_zero + payload

        # 3. Sum 16-bit big-endian words with odd padding and carry folding
        if len(full_buffer) % 2 != 0:
            full_buffer += b"\x00"

        total = sum((full_buffer[i] << 8) | full_buffer[i + 1] for i in range(0, len(full_buffer), 2))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        expected_chk = (~total) & 0xFFFF

        # Assert our class computed the exact same RFC-compliant value
        self.assertEqual(seg.checksum, expected_chk)

    def test_verify_checksum_valid_and_tampered(self) -> None:
        """Verify verify_checksum() passes on clean data and fails on corruption or wrong IPs."""
        src_ip = ip_from_str("10.0.0.1")
        dst_ip = ip_from_str("10.0.0.2")

        seg = TcpSegment(
            src_port=80,
            dst_port=54321,
            seq=1,
            ack=1,
            flags=FLAG_SYN | FLAG_ACK,
            window=32768,
            payload=b"RESPONSE_BODY",
        )
        seg.pack(src_ip, dst_ip)

        # 1. Clean segment validates
        self.assertTrue(seg.verify_checksum(src_ip, dst_ip))

        # 2. Tampered payload fails
        tampered_seg = TcpSegment(
            src_port=seg.src_port,
            dst_port=seg.dst_port,
            seq=seg.seq,
            ack=seg.ack,
            flags=seg.flags,
            window=seg.window,
            payload=b"RESPONSE_BODX",  # Corrupted 1 byte
        )
        tampered_seg.checksum = seg.checksum
        self.assertFalse(tampered_seg.verify_checksum(src_ip, dst_ip))

        # 3. Wrong source IP fails
        wrong_src_ip = ip_from_str("10.0.0.99")
        self.assertFalse(seg.verify_checksum(wrong_src_ip, dst_ip))

        # 4. Wrong destination IP fails
        wrong_dst_ip = ip_from_str("10.0.0.88")
        self.assertFalse(seg.verify_checksum(src_ip, wrong_dst_ip))

    def test_malformed_inputs(self) -> None:
        """Verify parse() returns None on truncated or invalid data_offset inputs."""
        self.assertIsNone(TcpSegment.parse(b""))
        self.assertIsNone(TcpSegment.parse(b"\x00" * 19))

        # Valid segment
        valid_bytes = TcpSegment(
            src_port=80,
            dst_port=80,
            seq=0,
            ack=0,
            flags=FLAG_SYN,
            window=1000,
        ).pack(ip_from_str("10.0.0.1"), ip_from_str("10.0.0.2"))

        # Mutate data_offset < 5 (e.g. data_offset = 4 -> 16 bytes, invalid for TCP)
        # offset_flags is at index 12-13
        bad_offset = valid_bytes[:12] + bytes([0x40, 0x02]) + valid_bytes[14:]
        self.assertIsNone(TcpSegment.parse(bad_offset))

        # Mutate data_offset > available length (e.g. data_offset = 10 -> 40 bytes, but raw is 20)
        oversized_offset = valid_bytes[:12] + bytes([0xA0, 0x02]) + valid_bytes[14:]
        self.assertIsNone(TcpSegment.parse(oversized_offset))

    def test_flag_bit_isolation(self) -> None:
        """Verify reserved bits are ignored on parse and only low 6 flag bits are extracted."""
        src_ip = ip_from_str("10.0.0.1")
        dst_ip = ip_from_str("10.0.0.2")

        seg = TcpSegment(
            src_port=1000,
            dst_port=2000,
            seq=10,
            ack=20,
            flags=FLAG_SYN | FLAG_FIN,
            window=4096,
        )
        packed = seg.pack(src_ip, dst_ip)

        # Deliberately pollute the 6 reserved bits in raw wire bytes (bits 6-11 of offset/flags)
        # offset_flags at index 12..13: data_offset=5 (0x50), flags=0x03 -> 0x5003
        # Set reserved bits -> 0x5FC3
        polluted_raw = packed[:12] + bytes([0x5F, 0xC3]) + packed[14:]

        parsed = TcpSegment.parse(polluted_raw)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        # Only low 6 bits (0x03 = SYN | FIN) should be extracted
        self.assertEqual(parsed.flags, FLAG_SYN | FLAG_FIN)

    def test_options_handling(self) -> None:
        """Verify options parsing, serialization, and payload boundary preservation."""
        src_ip = ip_from_str("10.0.0.1")
        dst_ip = ip_from_str("10.0.0.2")

        # 4 bytes of options: Maximum Segment Size (MSS = 1460 -> 0x02, 0x04, 0x05, 0xb4)
        mss_option = bytes([0x02, 0x04, 0x05, 0xB4])
        payload = b"PAYLOAD_AFTER_OPTIONS"

        seg = TcpSegment(
            src_port=80,
            dst_port=12345,
            seq=100,
            ack=200,
            flags=FLAG_ACK,
            window=65535,
            payload=payload,
            options=mss_option,
        )

        packed = seg.pack(src_ip, dst_ip)
        # 20 base + 4 options = 24 bytes header (data_offset = 6)
        self.assertEqual(seg.data_offset, 6)
        self.assertEqual(len(packed), 24 + len(payload))

        parsed = TcpSegment.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.data_offset, 6)
        self.assertEqual(parsed.options, mss_option)
        self.assertEqual(parsed.payload, payload)
        self.assertTrue(parsed.verify_checksum(src_ip, dst_ip))

    def test_tcp_over_ipv4_integration(self) -> None:
        """Full Layer 2 -> Layer 3 -> Layer 4 composition test."""
        client_mac = mac_from_str("52:54:00:11:22:33")
        server_mac = mac_from_str("02:00:00:00:00:02")
        client_ip = ip_from_str("10.0.0.1")
        server_ip = ip_from_str("10.0.0.2")

        # 1. Build TCP SYN segment
        tx_tcp = TcpSegment(
            src_port=49152,
            dst_port=80,
            seq=1000,
            ack=0,
            flags=FLAG_SYN,
            window=65535,
        )
        tcp_wire = tx_tcp.pack(src_ip=client_ip, dst_ip=server_ip)

        # 2. Wrap in IPv4 packet
        tx_ip = IPv4Packet(
            src_ip=client_ip,
            dst_ip=server_ip,
            protocol=PROTO_TCP,
            payload=tcp_wire,
        )
        ip_wire = tx_ip.pack()

        # 3. Wrap in Ethernet frame
        tx_eth = EthernetFrame(
            dst_mac=server_mac,
            src_mac=client_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ip_wire,
        )
        wire_frame = tx_eth.pack()

        # --- Stack Reception & Demux ---
        rx_eth = EthernetFrame.parse(wire_frame)
        self.assertIsNotNone(rx_eth)
        assert rx_eth is not None
        self.assertEqual(rx_eth.ethertype, ETHERTYPE_IPV4)

        rx_ip = IPv4Packet.parse(rx_eth.payload)
        self.assertIsNotNone(rx_ip)
        assert rx_ip is not None
        self.assertEqual(rx_ip.protocol, PROTO_TCP)
        self.assertEqual(rx_ip.dst_ip, server_ip)

        # Sliced payload from IPv4 passed to TCP
        rx_tcp = TcpSegment.parse(rx_ip.payload)
        self.assertIsNotNone(rx_tcp)
        assert rx_tcp is not None
        self.assertEqual(rx_tcp.src_port, 49152)
        self.assertEqual(rx_tcp.dst_port, 80)
        self.assertEqual(rx_tcp.flags, FLAG_SYN)

        # Pseudo-header verification dynamically using parsed IPv4 addresses
        self.assertTrue(rx_tcp.verify_checksum(rx_ip.src_ip, rx_ip.dst_ip))

    def test_no_socket_and_no_tcb_references(self) -> None:
        """Verify protocol/tcp.py contains zero socket APIs and zero references to connection state machines."""
        content = (Path(__file__).resolve().parent.parent / "protocol" / "tcp.py").read_text(encoding="utf-8")
        forbidden = [
            "socket.socket",
            "AF_INET",
            "SOCK_STREAM",
            "TcpState",
            "TCB",
            "ESTABLISHED",
            "SYN_SENT",
            "SYN_RCVD",
            "TIME_WAIT",
        ]
        for token in forbidden:
            self.assertNotIn(token, content, f"Forbidden reference '{token}' found in protocol/tcp.py")

    def test_tcp_repr(self) -> None:
        """Verify __repr__ includes ports, seq/ack, flags, window, and payload length."""
        seg = TcpSegment(
            src_port=80,
            dst_port=12345,
            seq=10,
            ack=20,
            flags=FLAG_SYN | FLAG_ACK,
            window=1024,
            payload=b"abc",
        )
        r = repr(seg)
        self.assertIn("sport=80", r)
        self.assertIn("dport=12345", r)
        self.assertIn("SYN|ACK", r)
        self.assertIn("payload_len=3", r)


if __name__ == "__main__":
    unittest.main()
