"""Tests for Address Resolution Protocol (protocol/arp.py)."""

import time
import unittest
from pathlib import Path

from protocol.arp import (
    ARP_CACHE_TTL,
    ARP_HLEN,
    ARP_HTYPE_ETHERNET,
    ARP_OP_REPLY,
    ARP_OP_REQUEST,
    ARP_PLEN,
    ARP_PTYPE_IPV4,
    ArpPacket,
    ArpTable,
    build_arp_reply,
    build_arp_request,
    handle_arp_frame,
    ip_from_str,
    ip_to_str,
)
from protocol.ethernet import (
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    EthernetFrame,
    mac_from_str,
    mac_to_str,
)


class TestArp(unittest.TestCase):
    """Unit and integration tests for ARP packets, ARP table, and frame handling."""

    def test_arp_constants(self) -> None:
        """Verify standard ARP protocol constants."""
        self.assertEqual(ARP_HTYPE_ETHERNET, 1)
        self.assertEqual(ARP_PTYPE_IPV4, 0x0800)
        self.assertEqual(ARP_HLEN, 6)
        self.assertEqual(ARP_PLEN, 4)
        self.assertEqual(ARP_OP_REQUEST, 1)
        self.assertEqual(ARP_OP_REPLY, 2)
        self.assertEqual(ARP_CACHE_TTL, 300)

    def test_ip_helpers_roundtrip(self) -> None:
        """Verify ip_to_str and ip_from_str round-trip conversion."""
        test_ips = [
            (b"\x0a\x00\x00\x01", "10.0.0.1"),
            (b"\x0a\x00\x00\x02", "10.0.0.2"),
            (b"\xc0\xa8\x01\x01", "192.168.1.1"),
            (b"\x00\x00\x00\x00", "0.0.0.0"),
            (b"\xff\xff\xff\xff", "255.255.255.255"),
        ]
        for ip_bytes, ip_string in test_ips:
            self.assertEqual(ip_to_str(ip_bytes), ip_string)
            self.assertEqual(ip_from_str(ip_string), ip_bytes)

        with self.assertRaises(ValueError):
            ip_from_str("10.0.0")  # 3 octets
        with self.assertRaises(ValueError):
            ip_from_str("10.0.0.256")  # out of range
        with self.assertRaises(ValueError):
            ip_from_str("10.0.0.abc")  # non-integer

    def test_arp_packet_pack_and_parse_roundtrip(self) -> None:
        """Verify complete pack and parse round-trip for ARP request and reply."""
        sender_mac = b"\x52\x54\x00\x12\x34\x56"
        sender_ip = b"\x0a\x00\x00\x01"
        target_mac = b"\x00\x00\x00\x00\x00\x00"
        target_ip = b"\x0a\x00\x00\x02"

        packet = ArpPacket(
            op=ARP_OP_REQUEST,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
        )
        raw = packet.pack()

        self.assertEqual(len(raw), 28, "Ethernet/IPv4 ARP packet must be exactly 28 bytes")

        parsed = ArpPacket.parse(raw)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.op, ARP_OP_REQUEST)
        self.assertEqual(parsed.sender_mac, sender_mac)
        self.assertEqual(parsed.sender_ip, sender_ip)
        self.assertEqual(parsed.target_mac, target_mac)
        self.assertEqual(parsed.target_ip, target_ip)

    def test_arp_packet_parse_malformed_input(self) -> None:
        """Verify parse() returns None for truncated or non-Ethernet/IPv4 packets."""
        self.assertIsNone(ArpPacket.parse(b""))
        self.assertIsNone(ArpPacket.parse(b"\x00" * 27))  # too short

        # Valid length, but wrong htype (e.g. 2 instead of 1)
        wrong_htype = ArpPacket(
            op=ARP_OP_REQUEST,
            sender_mac=b"\x00" * 6,
            sender_ip=b"\x00" * 4,
            target_mac=b"\x00" * 6,
            target_ip=b"\x00" * 4,
        ).pack()
        # Mutate htype to 2
        wrong_htype_bytes = b"\x00\x02" + wrong_htype[2:]
        self.assertIsNone(ArpPacket.parse(wrong_htype_bytes))

        # Wrong ptype (e.g. 0x86dd IPv6 instead of 0x0800 IPv4)
        wrong_ptype_bytes = wrong_htype[:2] + b"\x86\xdd" + wrong_htype[4:]
        self.assertIsNone(ArpPacket.parse(wrong_ptype_bytes))

    def test_arp_table_learn_lookup_and_expiration(self) -> None:
        """Verify ARP table storage, lookup, and TTL expiration."""
        table = ArpTable()
        ip = b"\x0a\x00\x00\x01"
        mac = b"\x52\x54\x00\x12\x34\x56"

        # Lookup unknown IP
        self.assertIsNone(table.lookup(ip))

        # Learn mapping
        table.learn(ip, mac)
        self.assertEqual(table.lookup(ip), mac)

        # Simulate expiration by backdating the timestamp
        table._entries[ip] = (mac, time.time() - (ARP_CACHE_TTL + 5))

        # Lookup should now return None and purge the stale entry
        self.assertIsNone(table.lookup(ip))
        self.assertNotIn(ip, table._entries)

    def test_arp_builders(self) -> None:
        """Verify build_arp_request and build_arp_reply construct valid Ethernet frames."""
        my_mac = b"\x00\x11\x22\x33\x44\x55"
        my_ip = b"\x0a\x00\x00\x02"
        target_ip = b"\x0a\x00\x00\x01"
        target_mac = b"\xaa\xbb\xcc\xdd\xee\xff"

        # Request
        req_frame = build_arp_request(my_mac, my_ip, target_ip)
        self.assertEqual(req_frame.dst_mac, BROADCAST_MAC)
        self.assertEqual(req_frame.src_mac, my_mac)
        self.assertEqual(req_frame.ethertype, ETHERTYPE_ARP)

        req_arp = ArpPacket.parse(req_frame.payload)
        self.assertIsNotNone(req_arp)
        assert req_arp is not None
        self.assertEqual(req_arp.op, ARP_OP_REQUEST)
        self.assertEqual(req_arp.sender_mac, my_mac)
        self.assertEqual(req_arp.sender_ip, my_ip)
        self.assertEqual(req_arp.target_mac, b"\x00" * 6)
        self.assertEqual(req_arp.target_ip, target_ip)

        # Reply
        rep_frame = build_arp_reply(my_mac, my_ip, target_mac, target_ip)
        self.assertEqual(rep_frame.dst_mac, target_mac)
        self.assertEqual(rep_frame.src_mac, my_mac)
        self.assertEqual(rep_frame.ethertype, ETHERTYPE_ARP)

        rep_arp = ArpPacket.parse(rep_frame.payload)
        self.assertIsNotNone(rep_arp)
        assert rep_arp is not None
        self.assertEqual(rep_arp.op, ARP_OP_REPLY)
        self.assertEqual(rep_arp.sender_mac, my_mac)
        self.assertEqual(rep_arp.sender_ip, my_ip)
        self.assertEqual(rep_arp.target_mac, target_mac)
        self.assertEqual(rep_arp.target_ip, target_ip)

    def test_handle_arp_frame_full_exchange(self) -> None:
        """Integration test for handle_arp_frame responding to requests for our IP."""
        my_mac = b"\x02\x00\x00\x00\x00\x02"
        my_ip = b"\x0a\x00\x00\x02"
        table = ArpTable()

        host_b_mac = b"\x52\x54\x00\x12\x34\x56"
        host_b_ip = b"\x0a\x00\x00\x01"

        # Host B asks: "Who has 10.0.0.2? Tell 10.0.0.1"
        inbound_arp = ArpPacket(
            op=ARP_OP_REQUEST,
            sender_mac=host_b_mac,
            sender_ip=host_b_ip,
            target_mac=b"\x00" * 6,
            target_ip=my_ip,
        )

        reply_frame = handle_arp_frame(inbound_arp.pack(), my_mac, my_ip, table)

        # Must return an EthernetFrame
        self.assertIsNotNone(reply_frame)
        assert reply_frame is not None

        # Frame checks
        self.assertEqual(reply_frame.ethertype, ETHERTYPE_ARP)
        self.assertEqual(reply_frame.dst_mac, host_b_mac, "Reply must be unicast directly to Host B")
        self.assertEqual(reply_frame.src_mac, my_mac)

        # Unpack payload
        outbound_arp = ArpPacket.parse(reply_frame.payload)
        self.assertIsNotNone(outbound_arp)
        assert outbound_arp is not None

        self.assertEqual(outbound_arp.op, ARP_OP_REPLY)
        self.assertEqual(outbound_arp.sender_ip, my_ip)
        self.assertEqual(outbound_arp.sender_mac, my_mac)
        self.assertEqual(outbound_arp.target_ip, host_b_ip)
        self.assertEqual(outbound_arp.target_mac, host_b_mac)

        # ARP Table must have learned Host B's mapping
        self.assertEqual(table.lookup(host_b_ip), host_b_mac)

    def test_handle_arp_frame_for_different_ip(self) -> None:
        """Verify handle_arp_frame ignores requests for IPs not owned by us, but still learns sender."""
        my_mac = b"\x02\x00\x00\x00\x00\x02"
        my_ip = b"\x0a\x00\x00\x02"
        table = ArpTable()

        host_b_mac = b"\x52\x54\x00\x12\x34\x56"
        host_b_ip = b"\x0a\x00\x00\x01"

        # Request for someone else (10.0.0.99)
        inbound_arp = ArpPacket(
            op=ARP_OP_REQUEST,
            sender_mac=host_b_mac,
            sender_ip=host_b_ip,
            target_mac=b"\x00" * 6,
            target_ip=b"\x0a\x00\x00\x63",  # 10.0.0.99
        )

        reply_frame = handle_arp_frame(inbound_arp.pack(), my_mac, my_ip, table)

        # Must NOT return a reply frame
        self.assertIsNone(reply_frame)

        # BUT must still learn sender's mapping
        self.assertEqual(table.lookup(host_b_ip), host_b_mac)

    def test_handle_arp_frame_malformed_input(self) -> None:
        """Verify handle_arp_frame returns None on malformed payload without raising."""
        table = ArpTable()
        self.assertIsNone(handle_arp_frame(b"short", b"\x00" * 6, b"\x00" * 4, table))

    def test_no_socket_references(self) -> None:
        """Verify that protocol/arp.py has zero references to OS socket modules."""
        content = (Path(__file__).resolve().parent.parent / "protocol" / "arp.py").read_text(encoding="utf-8")
        for token in ["socket", "AF_INET", "SOCK_STREAM", "SOCK_DGRAM"]:
            self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
