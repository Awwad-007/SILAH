# SILAH (صِلة) — User-Space TCP/IP Stack

> *A user-space TCP/IP stack forged in pure Python, bypassing the kernel one raw byte at a time.*

---

## Part 1: TUN/TAP Virtual Network Device Interface

Part 1 implements the foundational layer of SILAH: the interface to the Linux kernel's virtual network device subsystem (`/dev/net/tun`).

### Analogy
Think of SILAH's `/dev/net/tun` hook as a **private pneumatic tube directly into the kernel's networking room**. Instead of handing packets to the standard postal clerk (the kernel's own TCP/IP stack) and letting the OS dictate routing and socket semantics, this tube drops raw Ethernet frames directly onto a dedicated virtual wire between user-space and kernel-space.

---

## Architecture

```
+-------------------------------------------------------------------+
|                        User-Space (SILAH)                         |
|                                                                   |
|   +--------------------------+     +--------------------------+   |
|   |  async def recv()        |     |   def send(frame: bytes) |   |
|   |  (Retrieve single frame) |     |   (Atomic write to fd)   |   |
|   +------------^-------------+     +------------+-------------+   |
|                |                                |                 |
|         [asyncio.Queue]                         |                 |
|                |                                |                 |
|   +------------+-------------+                  |                 |
|   | Background Reader Task   |                  |                 |
|   | (loop.run_in_executor)   |                  |                 |
|   +------------^-------------+                  |                 |
|                |                                |                 |
|           os.read(fd)                      os.write(fd)           |
|                |                                |                 |
+----------------+--------------------------------+-----------------+
|                | /dev/net/tun (TAP Mode: Layer 2 Ethernet)        |
|                v                                v                 |
|                      Linux Kernel (tap0)                          |
+-------------------------------------------------------------------+
```

### Key Technical Properties
- **Device Mode**: `IFF_TAP (0x0002) | IFF_NO_PI (0x1000)` creates a pure Layer 2 Ethernet device with no 4-byte kernel packet info header.
- **`ioctl` Registration**: `TUNSETIFF = 0x400454CA` binds the open descriptor to `struct ifreq` (`16sH` byte layout).
- **Host-Side Setup**: Uses `iproute2` (`ip addr`, `ip link`) to assign IP, set MTU, and bring the link `UP`.
- **Asynchronous Read Path**: Background task runs non-blocking `os.read()` in thread executor, handles `BlockingIOError`, and delivers frames through `asyncio.Queue`.
- **Synchronous Write Path**: Direct, atomic `os.write()` of complete Ethernet frames.
- **Zero Sockets**: Completely eliminates `socket` module usage (`AF_INET`, `SOCK_STREAM` are absent).

---

---

## Part 2: Ethernet & ARP Protocol Layer

Part 2 implements Layer 2 Ethernet framing and Address Resolution Protocol (ARP) packet processing and caching.

### Analogy
- **Ethernet Frame**: The envelope for one single hop of a conveyor belt, stamped with physical sender/receiver hardware badges (MAC addresses) and an EtherType label declaring what cargo is packed inside.
- **ARP (Address Resolution Protocol)**: Shouting across a crowded office floor: *"Who owns IP 10.0.0.2? Please report back to 10.0.0.1!"* The true owner replies directly with their physical hardware MAC address.
- **ARP Table**: The receptionist's notebook where recently shouted physical badge numbers are jotted down on sticky notes that expire after 300 seconds (`ARP_CACHE_TTL`).

### Key Components
- [`protocol/ethernet.py`](file:///c:/Users/lenovo/Desktop/SILAH/protocol/ethernet.py):
  - `EthernetFrame`: Serializes and deserializes 14-byte Ethernet II frames (`!6s6sH`).
  - `mac_to_str` & `mac_from_str`: Fast, robust MAC address formatting and parsing.
- [`protocol/arp.py`](file:///c:/Users/lenovo/Desktop/SILAH/protocol/arp.py):
  - `ArpPacket`: 28-byte Ethernet/IPv4 ARP packet parser and packer (`!HHBBH6s4s6s4s`).
  - `ArpTable`: In-memory IP-to-MAC mapping cache with automatic TTL expiration.
  - `build_arp_request` & `build_arp_reply`: Helper builders for broadcast requests and unicast replies.
  - `handle_arp_frame`: Main protocol ingress function that learns sender mappings and automatically generates unicast replies when queried for our IP.

---

## Verification & Testing

### Tier 1 Automated Tests (No Root / No Kernel Device Required)
Runs anywhere without root privileges to validate:
- `struct ifreq` exact memory packing and flag preservation.
- Hardcoded constants (`TUNSETIFF`, `IFF_TAP`, `IFF_NO_PI`, ARP constants).
- Asynchronous reader and FIFO frame ordering through `asyncio.Queue`.
- Synchronous send pipeline and teardown idempotency.
- Ethernet and ARP packet pack/parse round-trips.
- ARP cache table storage, lookup, and TTL expiration.
- Full `handle_arp_frame` request/reply lifecycle and mapping learning.
- Total absence of OS socket API references.

Run automated tests:
```bash
python3 -m pytest -v tests/
```

### Tier 2 Manual Verification (Linux with `sudo` / Root)
To verify against the real Linux kernel network stack:

1. **Open and configure the virtual TAP device**:
   ```bash
   sudo python3 -c "
   import time
   from device.tun_tap import TunTapDevice

   dev = TunTapDevice(name='tap0', host_ip='10.0.0.1', prefix=24, mtu=1500)
   dev.open()
   print('Device tap0 successfully opened and configured!')
   print('Holding open for 15 seconds to inspect...')
   time.sleep(15)
   dev.close()
   print('Device closed cleanly.')
   "
   ```

2. **While the script is running, open another terminal and inspect the interface**:
   ```bash
   # Check interface state
   ip link show tap0

   # Check assigned IP address
   ip addr show dev tap0
   ```
   *Expected output:* `tap0` shows `state UP` with `inet 10.0.0.1/24 scope global tap0` and `mtu 1500`.

3. **Verify ping packet reception (Live Frame Echo)**:
   ```bash
   sudo python3 -c "
   import asyncio
   from device.tun_tap import TunTapDevice

   async def main():
       dev = TunTapDevice(name='tap0', host_ip='10.0.0.1', prefix=24)
       dev.open()
       dev.start()
       print('Waiting for raw Ethernet frames on tap0 (try running `ping 10.0.0.2` in another shell)...')
       frame = await dev.recv()
       print(f'Captured Ethernet frame ({len(frame)} bytes): {frame[:30].hex()}...')
       dev.close()

   asyncio.run(main())
   "
   ```
