"""Tests for Ethernet II framing (protocol/ethernet.py)."""

import unittest
from pathlib import Path

from protocol.ethernet import (
    BROADCAST_MAC,
    ETH_HEADER_LEN,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    mac_from_str,
    mac_to_str,
)


class TestEthernet(unittest.TestCase):
    """Unit tests for Ethernet frames and MAC address helpers."""

    def test_constants(self) -> None:
        """Verify standard Ethernet framing constants."""
        self.assertEqual(ETH_HEADER_LEN, 14)
        self.assertEqual(ETHERTYPE_IPV4, 0x0800)
        self.assertEqual(ETHERTYPE_ARP, 0x0806)
        self.assertEqual(BROADCAST_MAC, b"\xff\xff\xff\xff\xff\xff")

    def test_mac_string_conversion_roundtrip(self) -> None:
        """Verify mac_to_str and mac_from_str on multiple inputs including mixed case."""
        test_macs = [
            (b"\x52\x54\x00\x12\x34\x56", "52:54:00:12:34:56"),
            (b"\x00\x00\x00\x00\x00\x00", "00:00:00:00:00:00"),
            (b"\xff\xff\xff\xff\xff\xff", "ff:ff:ff:ff:ff:ff"),
            (b"\xaa\xbb\xcc\xdd\xee\xff", "aa:bb:cc:dd:ee:ff"),
        ]

        for mac_bytes, mac_string in test_macs:
            # mac_to_str
            self.assertEqual(mac_to_str(mac_bytes), mac_string)
            # mac_from_str
            self.assertEqual(mac_from_str(mac_string), mac_bytes)

        # Test mixed case and hyphen separators in mac_from_str
        self.assertEqual(mac_from_str("AA:bB:Cc:12:34:56"), b"\xaa\xbb\xcc\x12\x34\x56")
        self.assertEqual(mac_from_str("52-54-00-AB-CD-EF"), b"\x52\x54\x00\xab\xcd\xef")

    def test_mac_conversion_invalid_inputs(self) -> None:
        """Verify invalid MAC bytes/strings raise ValueError."""
        with self.assertRaises(ValueError):
            mac_to_str(b"\x01\x02\x03")  # too short
        with self.assertRaises(ValueError):
            mac_from_str("invalid_mac")
        with self.assertRaises(ValueError):
            mac_from_str("00:11:22:33:44")  # 5 octets
        with self.assertRaises(ValueError):
            mac_from_str("00:11:22:33:44:GG")  # invalid hex

    def test_ethernet_frame_pack_and_parse_roundtrip(self) -> None:
        """Verify complete pack and parse round-trip for valid Ethernet frame."""
        dst = b"\x00\x11\x22\x33\x44\x55"
        src = b"\xaa\xbb\xcc\xdd\xee\xff"
        ethertype = ETHERTYPE_IPV4
        payload = b"Hello IPv4 Payload 1234567890"

        frame = EthernetFrame(dst_mac=dst, src_mac=src, ethertype=ethertype, payload=payload)
        packed = frame.pack()

        self.assertEqual(len(packed), 14 + len(payload))

        parsed = EthernetFrame.parse(packed)
        self.assertIsNotNone(parsed)
        assert parsed is not None

        self.assertEqual(parsed.dst_mac, dst)
        self.assertEqual(parsed.src_mac, src)
        self.assertEqual(parsed.ethertype, ethertype)
        self.assertEqual(parsed.payload, payload)

    def test_ethernet_frame_malformed_input(self) -> None:
        """Verify parse() returns None for truncated or empty inputs."""
        self.assertIsNone(EthernetFrame.parse(b""))
        self.assertIsNone(EthernetFrame.parse(b"\x00" * 5))
        self.assertIsNone(EthernetFrame.parse(b"\x00" * 13))

        # Exactly 14 bytes header with empty payload is valid
        header_only = EthernetFrame.parse(b"\x00" * 14)
        self.assertIsNotNone(header_only)
        assert header_only is not None
        self.assertEqual(header_only.payload, b"")

    def test_ethernet_frame_repr(self) -> None:
        """Verify __repr__ provides clear debugging information."""
        frame = EthernetFrame(
            dst_mac=b"\xff\xff\xff\xff\xff\xff",
            src_mac=b"\x52\x54\x00\x12\x34\x56",
            ethertype=ETHERTYPE_ARP,
            payload=b"abc",
        )
        r = repr(frame)
        self.assertIn("ff:ff:ff:ff:ff:ff", r)
        self.assertIn("52:54:00:12:34:56", r)
        self.assertIn("0x0806", r)
        self.assertIn("payload_len=3", r)

    def test_no_socket_references(self) -> None:
        """Verify that protocol/ethernet.py has zero references to OS socket modules."""
        content = (Path(__file__).resolve().parent.parent / "protocol" / "ethernet.py").read_text(encoding="utf-8")
        for token in ["socket", "AF_INET", "SOCK_STREAM", "SOCK_DGRAM"]:
            self.assertNotIn(token, content)


if __name__ == "__main__":
    unittest.main()
