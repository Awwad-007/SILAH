"""Tier 1 Test Suite for SILAH Virtual Network Device (device/tun_tap.py).

These tests run without root privileges and without a real /dev/net/tun device.
They verify:
1. Hardcoded ioctl and flag constants against Linux kernel values.
2. struct ifreq byte-level memory packing and unpacking (16sH).
3. The async recv pipeline and background thread reader using OS pipes (os.pipe).
4. The synchronous send pipeline using OS pipes (os.pipe).
5. FIFO packet ordering and frame integrity.
6. Clean, idempotent resource closure and guardrails.
7. Verification that no OS socket APIs (AF_INET, SOCK_STREAM, etc.) are referenced.
"""

import asyncio
import os
import struct
import sys
import unittest
from pathlib import Path

from device.tun_tap import IFF_NO_PI, IFF_TAP, TUNSETIFF, TunTapDevice


class TestTunTapTier1(unittest.TestCase):
    """Tier 1 Unit & Integration Tests (No root, no real kernel device needed)."""

    def test_constants_values(self) -> None:
        """Verify hardcoded ioctl constants match Linux <linux/if_tun.h> definitions."""
        self.assertEqual(TUNSETIFF, 0x400454CA, "TUNSETIFF ioctl number must match 0x400454CA")
        self.assertEqual(IFF_TAP, 0x0002, "IFF_TAP flag must be 0x0002 (Layer 2 Ethernet)")
        self.assertEqual(IFF_NO_PI, 0x1000, "IFF_NO_PI flag must be 0x1000 (No packet info header)")

    def test_ifreq_struct_packing(self) -> None:
        """Verify struct ifreq memory layout: 16-byte null-padded name followed by 2-byte flags."""
        test_cases = [
            ("tap0", IFF_TAP | IFF_NO_PI),
            ("silah0", IFF_TAP),
            ("eth_custom99", IFF_NO_PI),
            ("a" * 15, IFF_TAP | IFF_NO_PI),  # Max allowed 15 chars + 1 null terminator
        ]

        for if_name, flags in test_cases:
            packed = TunTapDevice._pack_ifreq(if_name, flags)

            # C struct ifreq layout: 16 bytes for ifrn_name, 2 bytes for ifru_flags = 18 bytes
            self.assertEqual(len(packed), 18, f"Packed struct ifreq for '{if_name}' must be 18 bytes")
            self.assertEqual(len(packed), struct.calcsize("16sH"))

            # Unpack and verify fields
            name_bytes, flags_unpacked = struct.unpack("16sH", packed)
            decoded_name = name_bytes.rstrip(b"\x00").decode("ascii")

            self.assertEqual(decoded_name, if_name, "Unpacked interface name must match original")
            self.assertEqual(flags_unpacked, flags, "Unpacked flags must match original")

            if flags & IFF_TAP:
                self.assertTrue(flags_unpacked & IFF_TAP)
            if flags & IFF_NO_PI:
                self.assertTrue(flags_unpacked & IFF_NO_PI)

    def test_name_length_validation(self) -> None:
        """Verify that interface names longer than 15 characters are rejected on initialization."""
        with self.assertRaises(ValueError):
            TunTapDevice(name="interface_name_too_long")

    def test_no_socket_references_in_codebase(self) -> None:
        """Verify SILAH does not use or reference the OS socket layer (AF_INET, SOCK_STREAM, etc.)."""
        tun_tap_path = Path(__file__).resolve().parent.parent / "device" / "tun_tap.py"
        content = tun_tap_path.read_text(encoding="utf-8")

        forbidden_tokens = [
            "AF_INET",
            "AF_INET6",
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "socket.socket",
        ]

        for token in forbidden_tokens:
            self.assertNotIn(
                token,
                content,
                f"Forbidden socket reference '{token}' found in {tun_tap_path.name}. SILAH must not touch OS sockets.",
            )

    def test_sync_send_pipe_integration(self) -> None:
        """Integration test for synchronous send() using an OS pipe as the virtual device fd."""
        r_fd, w_fd = os.pipe()
        dev = TunTapDevice(name="tap_test")
        dev.fd = w_fd

        try:
            sample_frame = (
                b"\xff\xff\xff\xff\xff\xff"  # Dest MAC: Broadcast
                b"\x52\x54\x00\x12\x34\x56"  # Src MAC
                b"\x08\x06"                  # EtherType: ARP (0x0806)
                b"\x00\x01\x08\x00\x06\x04\x00\x01"
                b"\x52\x54\x00\x12\x34\x56\x0a\x00\x00\x02"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x01"
            )

            dev.send(sample_frame)

            read_back = os.read(r_fd, 4096)
            self.assertEqual(read_back, sample_frame, "Sent frame must match read-back frame exactly")
        finally:
            dev.close()
            try:
                os.close(r_fd)
            except OSError:
                pass

    def test_async_recv_pipe_integration(self) -> None:
        """Integration test for async recv() path and background reader using an OS pipe."""
        async def run_test() -> None:
            r_fd, w_fd = os.pipe()
            os.set_blocking(r_fd, False)
            dev = TunTapDevice(name="tap_test")
            dev.fd = r_fd

            try:
                dev.start()

                frame1 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00PAYLOAD_ONE"
                os.write(w_fd, frame1)

                received1 = await asyncio.wait_for(dev.recv(), timeout=2.0)
                self.assertEqual(received1, frame1, "First frame received must match frame written to pipe")

                frame2 = b"\xde\xad\xbe\xef\xca\xfe\x01\x02\x03\x04\x05\x06\x86\xddPAYLOAD_TWO_IPV6"
                os.write(w_fd, frame2)

                received2 = await asyncio.wait_for(dev.recv(), timeout=2.0)
                self.assertEqual(received2, frame2, "Second frame received must match frame written to pipe")
            finally:
                dev.close()
                try:
                    os.close(w_fd)
                except OSError:
                    pass

        asyncio.run(run_test())

    def test_fifo_packet_ordering(self) -> None:
        """Verify that multiple frames passing through the queue maintain strict FIFO order."""
        async def run_test() -> None:
            r_fd, w_fd = os.pipe()
            os.set_blocking(r_fd, False)
            dev = TunTapDevice(name="tap_test")
            dev.fd = r_fd

            try:
                dev.start()

                frames = [f"FRAME_{i:04d}_PAYLOAD".encode("ascii") for i in range(10)]
                received_frames = []

                for frame in frames:
                    os.write(w_fd, frame)
                    rec = await asyncio.wait_for(dev.recv(), timeout=2.0)
                    received_frames.append(rec)

                self.assertEqual(received_frames, frames, "Frames must be received in strict FIFO order")
            finally:
                dev.close()
                try:
                    os.close(w_fd)
                except OSError:
                    pass

        asyncio.run(run_test())

    def test_lifecycle_and_idempotency(self) -> None:
        """Verify device lifecycle state transitions, double-close idempotency, and send guards."""
        r_fd, w_fd = os.pipe()
        dev = TunTapDevice(name="tap_test")
        dev.fd = w_fd

        # Send succeeds when open
        dev.send(b"test_payload")
        os.close(r_fd)

        # Close cleanly
        dev.close()
        self.assertTrue(dev._closed)
        self.assertIsNone(dev.fd)

        # Double close must be idempotent (no exception)
        dev.close()

        # Send after close must raise RuntimeError
        with self.assertRaises(RuntimeError):
            dev.send(b"post_close_data")

        # Start after close must raise RuntimeError
        with self.assertRaises(RuntimeError):
            dev.start()

    def test_open_guardrails_on_non_linux_or_non_root(self) -> None:
        """Verify that open() fails cleanly with informative error on non-Linux or without root."""
        dev = TunTapDevice(name="tap_test")
        if sys.platform != "linux":
            with self.assertRaises(RuntimeError) as ctx:
                dev.open()
            self.assertIn("requires Linux", str(ctx.exception))
        elif hasattr(os, "geteuid") and os.geteuid() != 0:
            with self.assertRaises(PermissionError) as ctx:
                dev.open()
            self.assertIn("Root privileges", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
