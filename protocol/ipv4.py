"""Internet Protocol Version 4 (IPv4) for SILAH.

Analogy:
    Think of the IPv4 packet as the shipping label glued directly onto cargo inside
    the Ethernet envelope. While the Ethernet envelope only gets the cargo across
    one single hop of a conveyor belt, the IPv4 label carries the true originating
    address (source IP) and ultimate destination (destination IP) for the entire
    cross-network journey. It also has a hop-counter (TTL) stamped on it that gets
    decremented at each router stop so lost packages don't circulate forever.

Technical Details:
    An IPv4 header has a minimum length of 20 bytes (IHL = 5). It specifies the
    version, Type of Service (ToS), Total Length, Identification, Flags/Fragment
    Offset, Time to Live (TTL), higher-layer Protocol (e.g. 0x01 for ICMP, 0x06 for TCP),
    a 16-bit ones' complement header checksum, source IP, and destination IP,
    followed by optional variable-length options and the payload.
"""

import struct

# Reuse IP string formatting helpers from protocol.arp to maintain single source of truth
from protocol.arp import ip_from_str, ip_to_str

IPV4_MIN_HEADER_LEN: int = 20
PROTO_ICMP: int = 0x01
PROTO_TCP: int = 0x06  # Defined for reuse in Part 4+
PROTO_UDP: int = 0x11  # Defined for completeness


def checksum(data: bytes) -> int:
    """Compute the 16-bit ones' complement Internet Checksum (RFC 1071).

    Analogy:
        Think of this like re-adding a column of numbers on an invoice to catch typos.
        If the recipient re-adds all numbers including the negative total (checksum),
        the final sum comes out to exactly zero. If it doesn't, something got smudged.

    Technical Details:
        Computes the 16-bit ones' complement of the ones' complement sum of all 16-bit
        words in network byte order. If data length is odd, a trailing zero byte is
        appended before summing. Carry bits above bit 15 are folded into the lower 16 bits.
        When run on valid data with its checksum in place, the result is 0x0000.
    """
    if len(data) % 2 != 0:
        data = data + b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


class IPv4Packet:
    """IPv4 packet representation.

    Analogy:
        The universal shipping label carrying network-layer routing and integrity metadata.
    """

    __slots__ = (
        "version",
        "ihl",
        "tos",
        "total_len",
        "ident",
        "flags",
        "frag_offset",
        "ttl",
        "protocol",
        "checksum",
        "src_ip",
        "dst_ip",
        "options",
        "payload",
    )

    def __init__(
        self,
        src_ip: bytes,
        dst_ip: bytes,
        protocol: int,
        payload: bytes = b"",
        ttl: int = 64,
        ident: int = 0,
        flags: int = 0,
        frag_offset: int = 0,
        tos: int = 0,
        options: bytes = b"",
    ) -> None:
        self.version: int = 4
        self.options: bytes = options
        header_len = IPV4_MIN_HEADER_LEN + len(options)
        self.ihl: int = header_len // 4
        self.tos: int = tos
        self.payload: bytes = payload
        self.total_len: int = header_len + len(payload)
        self.ident: int = ident
        self.flags: int = flags
        self.frag_offset: int = frag_offset
        self.ttl: int = ttl
        self.protocol: int = protocol
        self.checksum: int = 0
        self.src_ip: bytes = src_ip
        self.dst_ip: bytes = dst_ip

    @classmethod
    def parse(cls, raw: bytes) -> "IPv4Packet | None":
        """Parse raw bytes into an IPv4Packet.

        Returns:
            IPv4Packet instance, or None if raw bytes are truncated, corrupted,
            have an invalid version/IHL, or fail header checksum validation.
        """
        if len(raw) < IPV4_MIN_HEADER_LEN:
            return None

        v_ihl = raw[0]
        version = v_ihl >> 4
        ihl = v_ihl & 0x0F

        if version != 4 or ihl < 5:
            return None

        header_len = ihl * 4
        if len(raw) < header_len:
            return None

        v_ihl, tos, total_len, ident, flags_frag, ttl, protocol, chk, src_ip, dst_ip = (
            struct.unpack("!BBHHHBBH4s4s", raw[:20])
        )

        if total_len < header_len or len(raw) < total_len:
            return None

        # Validate header checksum (must evaluate to 0 over the entire header)
        if checksum(raw[:header_len]) != 0:
            return None

        options = raw[20:header_len]
        # Slice payload using total_len to trim trailing Ethernet frame padding
        payload = raw[header_len:total_len]
        flags = flags_frag >> 13
        frag_offset = flags_frag & 0x1FFF

        pkt = cls(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            payload=payload,
            ttl=ttl,
            ident=ident,
            flags=flags,
            frag_offset=frag_offset,
            tos=tos,
            options=options,
        )
        pkt.ihl = ihl
        pkt.total_len = total_len
        pkt.checksum = chk
        return pkt

    def pack(self) -> bytes:
        """Serialize the IPv4 packet, calculating and embedding the header checksum."""
        header_len = IPV4_MIN_HEADER_LEN + len(self.options)
        ihl = header_len // 4
        total_len = header_len + len(self.payload)
        v_ihl = (4 << 4) | (ihl & 0x0F)
        flags_frag = ((self.flags & 0x07) << 13) | (self.frag_offset & 0x1FFF)

        # Pack header with checksum = 0
        hdr_zero = struct.pack(
            "!BBHHHBBH4s4s",
            v_ihl,
            self.tos,
            total_len,
            self.ident,
            flags_frag,
            self.ttl,
            self.protocol,
            0,
            self.src_ip,
            self.dst_ip,
        )
        full_hdr_zero = hdr_zero + self.options
        chk = checksum(full_hdr_zero)
        self.checksum = chk

        # Re-pack with computed checksum
        hdr_real = struct.pack(
            "!BBHHHBBH4s4s",
            v_ihl,
            self.tos,
            total_len,
            self.ident,
            flags_frag,
            self.ttl,
            self.protocol,
            chk,
            self.src_ip,
            self.dst_ip,
        )
        return hdr_real + self.options + self.payload

    def __repr__(self) -> str:
        src = ip_to_str(self.src_ip) if len(self.src_ip) == 4 else self.src_ip.hex()
        dst = ip_to_str(self.dst_ip) if len(self.dst_ip) == 4 else self.dst_ip.hex()
        return (
            f"IPv4Packet(src={src}, dst={dst}, proto=0x{self.protocol:02x}, "
            f"ttl={self.ttl}, total_len={self.total_len})"
        )
