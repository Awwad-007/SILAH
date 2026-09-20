"""Internet Control Message Protocol (ICMP) for SILAH.

Analogy:
    Think of an ICMP echo (ping) as someone tapping your shoulder with a specific
    rhythm (Echo Request), and you tapping back the exact same rhythm (Echo Reply)
    to prove you are awake, present, and paying attention. If any detail of the
    rhythm (identifier, sequence, or data payload) is altered, the sender knows
    the response is invalid.

Technical Details:
    ICMP operates as an IPv4 payload (protocol 0x01). For Echo messages, the ICMP
    header is 8 bytes:
      - 1 byte: Type (8 = Echo Request, 0 = Echo Reply)
      - 1 byte: Code (0 for echo messages)
      - 2 bytes: Internet Checksum (computed over the entire ICMP message, header + data)
      - 2 bytes: Identifier
      - 2 bytes: Sequence Number
    followed by an arbitrary data payload.
"""

import struct

from protocol.ipv4 import checksum

ICMP_ECHO_REPLY: int = 0
ICMP_ECHO_REQUEST: int = 8


class IcmpPacket:
    """ICMP message representation.

    Analogy:
        The heartbeat and diagnostic message exchanged across network nodes.
    """

    __slots__ = ("type", "code", "checksum", "identifier", "sequence", "data")

    def __init__(
        self,
        type_: int,
        code: int,
        identifier: int,
        sequence: int,
        data: bytes = b"",
        checksum: int = 0,
    ) -> None:
        self.type: int = type_
        self.code: int = code
        self.checksum: int = checksum
        self.identifier: int = identifier
        self.sequence: int = sequence
        self.data: bytes = data

    @classmethod
    def parse(cls, raw: bytes) -> "IcmpPacket | None":
        """Parse raw bytes into an IcmpPacket.

        Returns:
            IcmpPacket instance, or None if raw data is shorter than 8 bytes or fails
            the whole-message ICMP checksum validation.
        """
        if len(raw) < 8:
            return None

        # Validate whole-message checksum
        if checksum(raw) != 0:
            return None

        type_, code, chk, identifier, sequence = struct.unpack("!BBHHH", raw[:8])
        data = raw[8:]

        return cls(
            type_=type_,
            code=code,
            identifier=identifier,
            sequence=sequence,
            data=data,
            checksum=chk,
        )

    def pack(self) -> bytes:
        """Serialize the ICMP packet, calculating and embedding the whole-message checksum."""
        # Pack header with checksum = 0
        hdr_zero = struct.pack("!BBHHH", self.type, self.code, 0, self.identifier, self.sequence)
        msg_zero = hdr_zero + self.data
        chk = checksum(msg_zero)
        self.checksum = chk

        # Re-pack with computed checksum
        hdr_real = struct.pack(
            "!BBHHH", self.type, self.code, chk, self.identifier, self.sequence
        )
        return hdr_real + self.data

    def __repr__(self) -> str:
        t_name = (
            "ECHO_REQUEST"
            if self.type == ICMP_ECHO_REQUEST
            else ("ECHO_REPLY" if self.type == ICMP_ECHO_REPLY else str(self.type))
        )
        return (
            f"IcmpPacket(type={t_name}, code={self.code}, id={self.identifier}, "
            f"seq={self.sequence}, data_len={len(self.data)})"
        )


def build_echo_reply(request: IcmpPacket) -> IcmpPacket:
    """Construct an ICMP Echo Reply exactly mirroring the Echo Request's id, seq, and data."""
    return IcmpPacket(
        type_=ICMP_ECHO_REPLY,
        code=0,
        identifier=request.identifier,
        sequence=request.sequence,
        data=request.data,
    )
