"""Tests for ICMP Echo Request / Reply and full ping round-trip integration (protocol/icmp.py)."""

import unittest
from pathlib import Path

from protocol.arp import ip_from_str
from protocol.ethernet import ETHERTYPE_IPV4, EthernetFrame, mac_from_str
from protocol.icmp import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    IcmpPacket,
    build_echo_reply,
)
from protocol.ipv4 import PROTO_ICMP, IPv4Packet, checksum


class TestIcmp(unittest.TestCase):
    """Unit and integration tests for ICMP echo messages and ping pipeline."""

    def test_constants(self) -> None:
        """Verify ICMP Echo type codes."""
        self.assertEqual(ICMP_ECHO_REPLY, 0)
        self.assertEqual(ICMP_ECHO_REQUEST, 8)

    def test_icmp_packet_pack_and_parse_roundtrip(self) -> None:
        """Verify pack() and parse() round-trip for ICMP Echo Request and Reply."""
        data = b"0123456789abcdefghijklmnopqrstuvwxyz"
        req = IcmpPacket(
            type_=ICMP_ECHO_REQUEST,
            code=0,
            identifier=0xABCD,
            sequence=42,
            data=data,
        )

        packed = req.pack()
        self.assertEqual(len(packed), 8 + len(data))

        # Whole-message checksum must validate to 0
        self.assertEqual(checksum(packed), 0)

        parsed = IcmpPacket.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.type, ICMP_ECHO_REQUEST)
        self.assertEqual(parsed.code, 0)
        self.assertEqual(parsed.identifier, 0xABCD)
        self.assertEqual(parsed.sequence, 42)
        self.assertEqual(parsed.data, data)

    def test_icmp_malformed_input(self) -> None:
        """Verify parse() returns None for truncated or checksum-corrupted ICMP data."""
        self.assertIsNone(IcmpPacket.parse(b""))
        self.assertIsNone(IcmpPacket.parse(b"\x08\x00\x00\x00\x00\x01\x00"))  # 7 bytes (< 8)

        valid = IcmpPacket(
            type_=ICMP_ECHO_REQUEST,
            code=0,
            identifier=1,
            sequence=1,
            data=b"ping",
        ).pack()

        # Corrupt checksum
        corrupted = valid[:2] + bytes([valid[2] ^ 0xFF, valid[3]]) + valid[4:]
        self.assertIsNone(IcmpPacket.parse(corrupted))

        # Corrupt data payload (invalidates whole-message checksum)
        corrupted_data = valid[:-1] + b"X"
        self.assertIsNone(IcmpPacket.parse(corrupted_data))

    def test_build_echo_reply(self) -> None:
        """Verify build_echo_reply exactly mirrors identifier, sequence, and payload data."""
        req = IcmpPacket(
            type_=ICMP_ECHO_REQUEST,
            code=0,
            identifier=0x1234,
            sequence=99,
            data=b"EXACT_RHYTHM_PAYLOAD_12345",
        )

        reply = build_echo_reply(req)

        self.assertEqual(reply.type, ICMP_ECHO_REPLY)
        self.assertEqual(reply.code, 0)
        self.assertEqual(reply.identifier, req.identifier)
        self.assertEqual(reply.sequence, req.sequence)
        self.assertEqual(reply.data, req.data)

        # Ensure pack() on reply computes valid checksum
        packed_reply = reply.pack()
        self.assertEqual(checksum(packed_reply), 0)

    def test_icmp_repr(self) -> None:
        """Verify __repr__ formatting for request and reply."""
        req = IcmpPacket(type_=ICMP_ECHO_REQUEST, code=0, identifier=1, sequence=2, data=b"hi")
        self.assertIn("ECHO_REQUEST", repr(req))
        self.assertIn("data_len=2", repr(req))

        rep = IcmpPacket(type_=ICMP_ECHO_REPLY, code=0, identifier=1, sequence=2, data=b"hi")
        self.assertIn("ECHO_REPLY", repr(rep))

    def test_full_ping_flow_integration(self) -> None:
        """Simulate an entire end-to-end ping exchange (Ethernet -> IPv4 -> ICMP Request -> Reply)."""
        host_a_mac = mac_from_str("52:54:00:11:22:33")
        host_a_ip = ip_from_str("10.0.0.1")

        my_mac = mac_from_str("02:00:00:00:00:02")
        my_ip = ip_from_str("10.0.0.2")

        # 1. Host A constructs an ICMP Echo Request
        ping_data = b"TIMESTAMP_AND_RANDOM_ECHO_PAYLOAD_64BYTES"
        icmp_req = IcmpPacket(
            type_=ICMP_ECHO_REQUEST,
            code=0,
            identifier=0x7788,
            sequence=1,
            data=ping_data,
        )

        # 2. Host A wraps in IPv4 packet
        ip_req = IPv4Packet(
            src_ip=host_a_ip,
            dst_ip=my_ip,
            protocol=PROTO_ICMP,
            payload=icmp_req.pack(),
            ttl=64,
        )

        # 3. Host A wraps in Ethernet frame
        eth_req = EthernetFrame(
            dst_mac=my_mac,
            src_mac=host_a_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ip_req.pack(),
        )

        # Raw bytes on the virtual wire
        wire_inbound_bytes = eth_req.pack()

        # ------------------- SILAH Stack Processing -------------------
        # Step A: Parse Ethernet frame
        rx_eth = EthernetFrame.parse(wire_inbound_bytes)
        self.assertIsNotNone(rx_eth)
        assert rx_eth is not None
        self.assertEqual(rx_eth.ethertype, ETHERTYPE_IPV4)

        # Step B: Parse IPv4 packet
        rx_ip = IPv4Packet.parse(rx_eth.payload)
        self.assertIsNotNone(rx_ip)
        assert rx_ip is not None
        self.assertEqual(rx_ip.protocol, PROTO_ICMP)
        self.assertEqual(rx_ip.dst_ip, my_ip)

        # Step C: Parse ICMP packet
        rx_icmp = IcmpPacket.parse(rx_ip.payload)
        self.assertIsNotNone(rx_icmp)
        assert rx_icmp is not None
        self.assertEqual(rx_icmp.type, ICMP_ECHO_REQUEST)

        # Step D: Construct ICMP Echo Reply
        tx_icmp = build_echo_reply(rx_icmp)

        # Step E: Wrap in outbound IPv4 packet
        tx_ip = IPv4Packet(
            src_ip=my_ip,
            dst_ip=rx_ip.src_ip,
            protocol=PROTO_ICMP,
            payload=tx_icmp.pack(),
            ttl=64,
        )

        # Step F: Wrap in outbound Ethernet frame
        tx_eth = EthernetFrame(
            dst_mac=rx_eth.src_mac,
            src_mac=my_mac,
            ethertype=ETHERTYPE_IPV4,
            payload=tx_ip.pack(),
        )

        wire_outbound_bytes = tx_eth.pack()

        # ------------------- Verification of Response -------------------
        # Validate outbound wire frame
        resp_eth = EthernetFrame.parse(wire_outbound_bytes)
        self.assertIsNotNone(resp_eth)
        assert resp_eth is not None
        self.assertEqual(resp_eth.dst_mac, host_a_mac)
        self.assertEqual(resp_eth.src_mac, my_mac)

        resp_ip = IPv4Packet.parse(resp_eth.payload)
        self.assertIsNotNone(resp_ip)
        assert resp_ip is not None
        self.assertEqual(resp_ip.src_ip, my_ip)
        self.assertEqual(resp_ip.dst_ip, host_a_ip)
        self.assertEqual(resp_ip.protocol, PROTO_ICMP)

        resp_icmp = IcmpPacket.parse(resp_ip.payload)
        self.assertIsNotNone(resp_icmp)
        assert resp_icmp is not None
        self.assertEqual(resp_icmp.type, ICMP_ECHO_REPLY)
        self.assertEqual(resp_icmp.code, 0)
        self.assertEqual(resp_icmp.identifier, 0x7788)
        self.assertEqual(resp_icmp.sequence, 1)
        self.assertEqual(resp_icmp.data, ping_data)

    def test_no_socket_references(self) -> None:
        """Verify protocol/icmp.py has zero references to OS socket creation APIs."""
        content = (Path(__file__).resolve().parent.parent / "protocol" / "icmp.py").read_text(encoding="utf-8")
        for token in ["socket.socket", "AF_INET", "SOCK_STREAM", "SOCK_DGRAM"]:
            self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
