"""Transmission Control Protocol (TCP) Header & Pseudo-Header Layer for SILAH.

Analogy:
    Think of the TCP header as the numbered-pages system inside the shipping package.
    Every byte shipped gets a running page number (sequence number), and the far end
    confirms how many continuous pages it has received so far (acknowledgment number).
    The flag bits act as checkboxes stamped on the envelope (e.g. SYN = "let's start
    a conversation", ACK = "I got what you sent", FIN = "I'm done sending").
    The pseudo-header checksum acts as TCP borrowing the delivery address off the outer
    shipping envelope before sealing its tamper-proof seal — so a segment quietly
    delivered to the wrong house gets caught immediately.

Technical Details:
    A TCP segment has a minimum 20-byte header:
      - 2 bytes Source Port, 2 bytes Destination Port
      - 4 bytes Sequence Number, 4 bytes Acknowledgment Number
      - 2 bytes Data Offset (top 4 bits) + Reserved (6 bits) + Flags (low 6 bits: URG, ACK, PSH, RST, SYN, FIN)
      - 2 bytes Window Size
      - 2 bytes Internet Checksum (computed across a 12-byte IPv4 pseudo-header + TCP header + options + payload)
      - 2 bytes Urgent Pointer
      - Variable-length Options (if Data Offset > 5)
      - Payload
"""

import struct

from protocol.ipv4 import checksum

TCP_MIN_HEADER_LEN: int = 20

# TCP Flag bitmasks (matching the low 6 bits of the 16-bit offset/flags field)
FLAG_FIN: int = 0x01
FLAG_SYN: int = 0x02
FLAG_RST: int = 0x04
FLAG_PSH: int = 0x08
FLAG_ACK: int = 0x10
FLAG_URG: int = 0x20


def flags_to_str(flags: int) -> str:
    """Format TCP flag bits into a human-readable string (e.g. 'SYN|ACK' or '-').

    Display order: SYN, ACK, FIN, RST, PSH, URG.
    """
    order = [
        (FLAG_SYN, "SYN"),
        (FLAG_ACK, "ACK"),
        (FLAG_FIN, "FIN"),
        (FLAG_RST, "RST"),
        (FLAG_PSH, "PSH"),
        (FLAG_URG, "URG"),
    ]
    active = [name for bit, name in order if flags & bit]
    return "|".join(active) if active else "-"


class TcpSegment:
    """TCP segment representation.

    Analogy:
        A single numbered parcel in the ordered byte-stream delivery system.
    """

    __slots__ = (
        "src_port",
        "dst_port",
        "seq",
        "ack",
        "data_offset",
        "flags",
        "window",
        "checksum",
        "urgent_ptr",
        "options",
        "payload",
    )

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        payload: bytes = b"",
        options: bytes = b"",
        urgent_ptr: int = 0,
    ) -> None:
        self.src_port: int = src_port
        self.dst_port: int = dst_port
        self.seq: int = seq
        self.ack: int = ack
        self.flags: int = flags & 0x3F
        self.window: int = window
        self.payload: bytes = payload
        self.options: bytes = options
        self.urgent_ptr: int = urgent_ptr
        self.data_offset: int = (TCP_MIN_HEADER_LEN + len(options)) // 4
        self.checksum: int = 0

    @classmethod
    def parse(cls, raw: bytes) -> "TcpSegment | None":
        """Parse raw bytes into a TcpSegment.

        Returns:
            TcpSegment instance, or None if raw data is shorter than 20 bytes or
            data_offset claims an invalid header length.
        """
        if len(raw) < TCP_MIN_HEADER_LEN:
            return None

        src_port, dst_port, seq, ack, offset_flags, window, chk, urgent_ptr = (
            struct.unpack("!HHIIHHHH", raw[:20])
        )

        data_offset = (offset_flags >> 12) & 0x0F
        header_len = data_offset * 4

        if header_len < TCP_MIN_HEADER_LEN or len(raw) < header_len:
            return None

        flags = offset_flags & 0x003F
        options = raw[20:header_len]
        payload = raw[header_len:]

        seg = cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            payload=payload,
            options=options,
            urgent_ptr=urgent_ptr,
        )
        seg.data_offset = data_offset
        seg.checksum = chk
        return seg

    @staticmethod
    def _build_pseudo_header(src_ip: bytes, dst_ip: bytes, tcp_len: int) -> bytes:
        """Construct the 12-byte IPv4 pseudo-header (RFC 793)."""
        return struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 6, tcp_len)

    def pack(self, src_ip: bytes, dst_ip: bytes) -> bytes:
        """Serialize the TCP segment and compute the pseudo-header checksum."""
        self.data_offset = (TCP_MIN_HEADER_LEN + len(self.options)) // 4
        offset_flags = ((self.data_offset & 0x0F) << 12) | (self.flags & 0x003F)

        hdr_zero = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            offset_flags,
            self.window,
            0,
            self.urgent_ptr,
        )

        segment_zero = hdr_zero + self.options + self.payload
        pseudo_hdr = self._build_pseudo_header(src_ip, dst_ip, len(segment_zero))

        chk = checksum(pseudo_hdr + segment_zero)
        self.checksum = chk

        hdr_real = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            offset_flags,
            self.window,
            chk,
            self.urgent_ptr,
        )
        return hdr_real + self.options + self.payload

    def verify_checksum(self, src_ip: bytes, dst_ip: bytes) -> bool:
        """Verify the segment's checksum using the IPv4 pseudo-header."""
        data_offset = (TCP_MIN_HEADER_LEN + len(self.options)) // 4
        offset_flags = ((data_offset & 0x0F) << 12) | (self.flags & 0x003F)

        hdr_actual = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            offset_flags,
            self.window,
            self.checksum,
            self.urgent_ptr,
        )

        full_segment = hdr_actual + self.options + self.payload
        pseudo_hdr = self._build_pseudo_header(src_ip, dst_ip, len(full_segment))

        return checksum(pseudo_hdr + full_segment) == 0

    def __repr__(self) -> str:
        return (
            f"TcpSegment(sport={self.src_port}, dport={self.dst_port}, "
            f"seq={self.seq}, ack={self.ack}, flags={flags_to_str(self.flags)}, "
            f"win={self.window}, payload_len={len(self.payload)})"
        )
