"""Ethernet II (Layer 2) Framing for SILAH.

Analogy:
    Think of an Ethernet frame as the envelope for one hop of a conveyor belt.
    Stamped on the outside are the physical hardware badges of the sender and
    immediate receiver (MAC addresses), alongside a label (EtherType) telling
    the recipient what type of cargo is packed inside the envelope.

Technical Details:
    An Ethernet II frame starts with a 14-byte header:
      - 6 bytes: Destination MAC address
      - 6 bytes: Source MAC address
      - 2 bytes: EtherType (e.g. 0x0800 for IPv4, 0x0806 for ARP)
    followed by the payload for the specified higher-layer protocol.
"""

import struct

ETH_HEADER_LEN: int = 14
ETHERTYPE_IPV4: int = 0x0800
ETHERTYPE_ARP: int = 0x0806
BROADCAST_MAC: bytes = b"\xff\xff\xff\xff\xff\xff"


def mac_to_str(mac: bytes) -> str:
    """Format 6 raw MAC bytes into lowercase colon-separated hex (aa:bb:cc:dd:ee:ff)."""
    if len(mac) != 6:
        raise ValueError(f"Expected 6 bytes for MAC address, got {len(mac)}")
    return ":".join(f"{b:02x}" for b in mac)


def mac_from_str(s: str) -> bytes:
    """Parse a colon- or hyphen-separated hex MAC address string into 6 raw bytes."""
    clean = s.replace(":", "").replace("-", "").strip()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address string format: '{s}'")
    try:
        return bytes.fromhex(clean)
    except ValueError as e:
        raise ValueError(f"Invalid hex in MAC address '{s}': {e}") from e


class EthernetFrame:
    """Ethernet II Layer 2 frame representation.

    Analogy:
        The physical envelope passed between adjacent network nodes on the same wire.
    """

    __slots__ = ("dst_mac", "src_mac", "ethertype", "payload")

    def __init__(
        self,
        dst_mac: bytes,
        src_mac: bytes,
        ethertype: int,
        payload: bytes = b"",
    ) -> None:
        self.dst_mac: bytes = dst_mac
        self.src_mac: bytes = src_mac
        self.ethertype: int = ethertype
        self.payload: bytes = payload

    @classmethod
    def parse(cls, raw: bytes) -> "EthernetFrame | None":
        """Parse raw frame bytes into an EthernetFrame.

        Returns:
            EthernetFrame instance, or None if the raw data is shorter than the 14-byte header.
        """
        if len(raw) < ETH_HEADER_LEN:
            return None
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw[:ETH_HEADER_LEN])
        payload = raw[ETH_HEADER_LEN:]
        return cls(dst_mac, src_mac, ethertype, payload)

    def pack(self) -> bytes:
        """Serialize the Ethernet header and payload into raw wire bytes."""
        return struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.ethertype) + self.payload

    def __repr__(self) -> str:
        dst = mac_to_str(self.dst_mac) if len(self.dst_mac) == 6 else self.dst_mac.hex()
        src = mac_to_str(self.src_mac) if len(self.src_mac) == 6 else self.src_mac.hex()
        return (
            f"EthernetFrame(dst={dst}, src={src}, "
            f"ethertype=0x{self.ethertype:04x}, payload_len={len(self.payload)})"
        )
