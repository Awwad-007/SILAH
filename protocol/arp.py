"""Address Resolution Protocol (ARP) for SILAH.

Analogy:
    Think of ARP as shouting a street address across a crowded office floor:
    "Who owns desk address 10.0.0.2? Please report back to 10.0.0.1!"
    The host that actually owns that IP shouts back directly with their physical
    badge number (MAC address). Everyone who hears the announcement writes down
    the sender's badge number on a sticky note in their desk notebook (the ARP table)
    so they don't have to shout again next time.

Technical Details:
    ARP operates directly above Ethernet (EtherType 0x0806). For IPv4 over Ethernet,
    an ARP packet is 28 bytes with hardware type 1 (Ethernet) and protocol type
    0x0800 (IPv4). This module parses incoming ARP requests/replies, maintains an
    in-memory cache with TTL expiration, and builds outbound request/reply frames.
"""

import struct
import time

from protocol.ethernet import (
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    EthernetFrame,
    mac_to_str,
)

ARP_HTYPE_ETHERNET: int = 1
ARP_PTYPE_IPV4: int = 0x0800
ARP_HLEN: int = 6
ARP_PLEN: int = 4
ARP_OP_REQUEST: int = 1
ARP_OP_REPLY: int = 2
ARP_CACHE_TTL: int = 300  # Entry expiration lifetime in seconds


def ip_to_str(ip: bytes) -> str:
    """Format 4 raw IPv4 bytes into a dotted-decimal string (e.g. 10.0.0.1)."""
    if len(ip) != 4:
        raise ValueError(f"Expected 4 bytes for IPv4 address, got {len(ip)}")
    return f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"


def ip_from_str(s: str) -> bytes:
    """Parse a dotted-decimal IPv4 string (e.g. 10.0.0.1) into 4 raw bytes."""
    parts = s.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4 string format: '{s}'")
    try:
        octets = [int(p) for p in parts]
    except ValueError as e:
        raise ValueError(f"Invalid integer in IPv4 string '{s}': {e}") from e

    for octet in octets:
        if not (0 <= octet <= 255):
            raise ValueError(f"IPv4 octet out of range (0-255): {octet} in '{s}'")

    return bytes(octets)


class ArpPacket:
    """ARP packet for Ethernet hardware and IPv4 protocol.

    Analogy:
        The paper announcement card containing sender and target IP and MAC addresses.
    """

    __slots__ = ("op", "sender_mac", "sender_ip", "target_mac", "target_ip")

    def __init__(
        self,
        op: int,
        sender_mac: bytes,
        sender_ip: bytes,
        target_mac: bytes,
        target_ip: bytes,
    ) -> None:
        self.op: int = op
        self.sender_mac: bytes = sender_mac
        self.sender_ip: bytes = sender_ip
        self.target_mac: bytes = target_mac
        self.target_ip: bytes = target_ip

    @classmethod
    def parse(cls, raw: bytes) -> "ArpPacket | None":
        """Parse raw bytes into an ArpPacket.

        Returns:
            ArpPacket instance if valid Ethernet/IPv4 ARP, or None if malformed/unsupported.
        """
        # ARP for Ethernet + IPv4 is exactly 28 bytes
        if len(raw) < 28:
            return None

        htype, ptype, hlen, plen, op, sender_mac, sender_ip, target_mac, target_ip = (
            struct.unpack("!HHBBH6s4s6s4s", raw[:28])
        )

        if (
            htype != ARP_HTYPE_ETHERNET
            or ptype != ARP_PTYPE_IPV4
            or hlen != ARP_HLEN
            or plen != ARP_PLEN
        ):
            return None

        return cls(op, sender_mac, sender_ip, target_mac, target_ip)

    def pack(self) -> bytes:
        """Serialize the ARP packet into 28 raw bytes."""
        return struct.pack(
            "!HHBBH6s4s6s4s",
            ARP_HTYPE_ETHERNET,
            ARP_PTYPE_IPV4,
            ARP_HLEN,
            ARP_PLEN,
            self.op,
            self.sender_mac,
            self.sender_ip,
            self.target_mac,
            self.target_ip,
        )

    def __repr__(self) -> str:
        op_name = "REQUEST" if self.op == ARP_OP_REQUEST else ("REPLY" if self.op == ARP_OP_REPLY else str(self.op))
        s_ip = ip_to_str(self.sender_ip) if len(self.sender_ip) == 4 else self.sender_ip.hex()
        t_ip = ip_to_str(self.target_ip) if len(self.target_ip) == 4 else self.target_ip.hex()
        s_mac = mac_to_str(self.sender_mac) if len(self.sender_mac) == 6 else self.sender_mac.hex()
        t_mac = mac_to_str(self.target_mac) if len(self.target_mac) == 6 else self.target_mac.hex()
        return f"ArpPacket(op={op_name}, sender=[{s_ip} / {s_mac}], target=[{t_ip} / {t_mac}])"


class ArpTable:
    """In-memory cache mapping IPv4 addresses to physical MAC addresses.

    Analogy:
        The receptionist's desk notebook where recently shouted physical badge numbers
        are jotted down on sticky notes that expire after a set time limit (ARP_CACHE_TTL).
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        # Internal dict mapping IP bytes -> (mac bytes, learned_at timestamp)
        self._entries: dict[bytes, tuple[bytes, float]] = {}

    def learn(self, ip: bytes, mac: bytes) -> None:
        """Record or refresh an IP-to-MAC mapping with current timestamp."""
        self._entries[ip] = (mac, time.time())

    def lookup(self, ip: bytes) -> bytes | None:
        """Lookup a MAC address for the given IP bytes. Returns None if unknown or expired."""
        if ip not in self._entries:
            return None

        mac, learned_at = self._entries[ip]
        if (time.time() - learned_at) > ARP_CACHE_TTL:
            del self._entries[ip]
            return None

        return mac

    def __repr__(self) -> str:
        now = time.time()
        active = [
            f"{ip_to_str(ip)} -> {mac_to_str(mac)}"
            for ip, (mac, ts) in self._entries.items()
            if (now - ts) <= ARP_CACHE_TTL
        ]
        return f"ArpTable({', '.join(active)})"


def build_arp_request(my_mac: bytes, my_ip: bytes, target_ip: bytes) -> EthernetFrame:
    """Build an outbound ARP request packet wrapped in a broadcast Ethernet frame."""
    arp = ArpPacket(
        op=ARP_OP_REQUEST,
        sender_mac=my_mac,
        sender_ip=my_ip,
        target_mac=b"\x00" * 6,
        target_ip=target_ip,
    )
    return EthernetFrame(
        dst_mac=BROADCAST_MAC,
        src_mac=my_mac,
        ethertype=ETHERTYPE_ARP,
        payload=arp.pack(),
    )


def build_arp_reply(
    my_mac: bytes, my_ip: bytes, their_mac: bytes, their_ip: bytes
) -> EthernetFrame:
    """Build an outbound ARP reply packet wrapped in a unicast Ethernet frame."""
    arp = ArpPacket(
        op=ARP_OP_REPLY,
        sender_mac=my_mac,
        sender_ip=my_ip,
        target_mac=their_mac,
        target_ip=their_ip,
    )
    return EthernetFrame(
        dst_mac=their_mac,
        src_mac=my_mac,
        ethertype=ETHERTYPE_ARP,
        payload=arp.pack(),
    )


def handle_arp_frame(
    raw_payload: bytes, my_mac: bytes, my_ip: bytes, table: ArpTable
) -> EthernetFrame | None:
    """Process an incoming ARP packet payload and conditionally produce a reply frame.

    Actions:
        1. Parse raw_payload as an ArpPacket (returns None on malformed bytes).
        2. Opportunistically learn sender_ip -> sender_mac into ArpTable.
        3. If it is an ARP Request for my_ip, build and return a unicast ARP reply frame.
        4. Otherwise, return None.
    """
    packet = ArpPacket.parse(raw_payload)
    if packet is None:
        return None

    # Always learn sender mapping from valid ARP traffic
    table.learn(packet.sender_ip, packet.sender_mac)

    if packet.op == ARP_OP_REQUEST and packet.target_ip == my_ip:
        return build_arp_reply(
            my_mac=my_mac,
            my_ip=my_ip,
            their_mac=packet.sender_mac,
            their_ip=packet.sender_ip,
        )

    return None
