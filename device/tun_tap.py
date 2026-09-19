"""TUN/TAP Virtual Network Device Interface for SILAH.

Analogy:
    Think of SILAH's /dev/net/tun hook as a private pneumatic tube directly into
    the kernel's networking room. Instead of passing messages through the standard
    postal clerk (the OS kernel's own TCP/IP stack) and letting the OS dictate
    routing and protocol handling, this tube drops raw Ethernet frames directly
    onto a virtual wire connecting user-space to kernel-space.

Technical Details:
    This module registers a TAP (Layer 2) virtual network device using `/dev/net/tun`
    and `ioctl(TUNSETIFF)`. It bypasses the kernel's Layer 3/4 network stack entirely,
    giving SILAH direct control over raw Layer 2 Ethernet frames entering and leaving
    the machine. No kernel socket APIs are used.
"""

import asyncio
import os
import struct
import subprocess
import sys

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

# Linux /dev/net/tun ioctl constants (from <linux/if_tun.h>)
TUNSETIFF: int = 0x400454CA
IFF_TAP: int = 0x0002
IFF_NO_PI: int = 0x1000


class TunTapDevice:
    """User-space controller for a Linux TAP virtual network interface.

    Analogy:
        Think of this class as the hatch operator at our end of the pneumatic tube.
        When opened, it establishes the channel to the kernel. Frames pushed down
        via `send()` emerge immediately on the kernel's virtual link; frames emitted
        by the kernel arrive at our hatch and are placed into an internal basket
        (`asyncio.Queue`) for `recv()` to retrieve one by one.

    Technical Details:
        Manages the raw file descriptor for `/dev/net/tun`, performs `ioctl` registration,
        configures host-side network settings via `iproute2`, and provides an asynchronous
        event-loop-friendly frame reader alongside a synchronous zero-copy writer.
    """

    def __init__(
        self,
        name: str = "tap0",
        host_ip: str = "10.0.0.1",
        prefix: int = 24,
        mtu: int = 1500,
    ) -> None:
        if len(name.encode("ascii", errors="replace")) >= 16:
            raise ValueError(f"Interface name '{name}' exceeds maximum length of 15 bytes")

        self.name: str = name
        self.host_ip: str = host_ip
        self.prefix: int = prefix
        self.mtu: int = mtu
        self.fd: int | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None
        self._closed: bool = False

    @staticmethod
    def _pack_ifreq(name: str, flags: int) -> bytes:
        """Pack interface name and flags into a C struct ifreq layout (16sH).

        Layout:
            - 16 bytes: null-padded interface name string
            - 2 bytes (unsigned short): configuration flags (IFF_TAP | IFF_NO_PI)
        """
        return struct.pack("16sH", name.encode("ascii"), flags)

    def open(self) -> None:
        """Open /dev/net/tun, register TAP device with kernel, and configure link.

        Raises:
            RuntimeError: If executed on non-Linux OS where /dev/net/tun is unavailable.
            PermissionError: If executed without root (CAP_NET_ADMIN) privileges.
            subprocess.CalledProcessError: If `ip` configuration command fails.
        """
        if sys.platform != "linux" or fcntl is None:
            raise RuntimeError(
                f"SILAH TUN/TAP interface requires Linux (/dev/net/tun). "
                f"Current platform: {sys.platform}"
            )

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError(
                "Root privileges (CAP_NET_ADMIN) required to create and configure TAP interface."
            )

        fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = self._pack_ifreq(self.name, IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        os.set_blocking(fd, False)
        self.fd = fd
        self._closed = False

        self._configure_host()

    def _configure_host(self) -> None:
        """Configure the kernel's host-side view of the TAP interface via iproute2."""
        subprocess.run(
            ["ip", "addr", "add", f"{self.host_ip}/{self.prefix}", "dev", self.name],
            check=True,
        )
        subprocess.run(
            ["ip", "link", "set", "dev", self.name, "up"],
            check=True,
        )
        subprocess.run(
            ["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)],
            check=True,
        )

    def start(self) -> None:
        """Start the background asynchronous reader task.

        Must be called once from within an active asyncio event loop after `open()`,
        before calling `recv()`.
        """
        if self.fd is None or self._closed:
            raise RuntimeError("Cannot start reader: device is not open or already closed.")
        if self._reader_task is not None and not self._reader_task.done():
            return

        loop = asyncio.get_running_loop()
        self._reader_task = loop.create_task(self._reader_loop())

    async def _reader_loop(self) -> None:
        """Background loop reading raw Ethernet frames and enqueuing them."""
        loop = asyncio.get_running_loop()
        # Ethernet max frame buffer size: MTU + 14 (Ethernet header) + 4 (VLAN/FCS)
        bufsize = max(self.mtu + 18, 4096)

        while not self._closed and self.fd is not None:
            try:
                data = await loop.run_in_executor(None, os.read, self.fd, bufsize)
            except BlockingIOError:
                # Non-blocking descriptor with no data ready; yield briefly
                await asyncio.sleep(0.001)
                continue
            except (OSError, ValueError):
                # When closed or interrupted
                if self._closed:
                    break
                raise
            except asyncio.CancelledError:
                break

            if not data:
                # EOF / descriptor closed
                break

            await self._queue.put(data)

    async def recv(self) -> bytes:
        """Await and return the next raw Layer 2 Ethernet frame from the queue."""
        return await self._queue.get()

    def send(self, frame: bytes) -> None:
        """Synchronously write a raw Layer 2 Ethernet frame directly to the TAP fd."""
        if self.fd is None or self._closed:
            raise RuntimeError("Cannot send frame: device is not open or already closed.")
        os.write(self.fd, frame)

    def close(self) -> None:
        """Release the virtual device file descriptor and stop background tasks."""
        if self._closed:
            return
        self._closed = True

        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()

        if self.fd is not None:
            fd_to_close = self.fd
            self.fd = None
            try:
                os.close(fd_to_close)
            except OSError:
                pass
