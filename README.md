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

---

## Part 3: IPv4 & ICMP (Ping) Protocol Layer

Part 3 implements Layer 3 IPv4 packet processing, RFC 1071 internet checksumming, and ICMP Echo Request / Reply (ping) mirroring.

### Analogy
- **IPv4 Packet**: The universal shipping label glued onto cargo inside the Ethernet envelope. Valid for the entire cross-network journey, it carries origin/destination IP addresses and a TTL hop-counter stamped on it to prevent lost packages from circulating forever.
- **Internet Checksum**: Re-adding a column of numbers on an invoice to catch typos. If the recipient re-adds all numbers including the negative total (checksum), the final sum evaluates to exactly zero.
- **ICMP Echo (Ping)**: Someone tapping your shoulder with a specific rhythm (Echo Request), and you tapping back the exact same rhythm (Echo Reply) with identical identifier, sequence, and payload data to prove you are awake and listening.

### Key Components
- [`protocol/ipv4.py`](file:///c:/Users/lenovo/Desktop/SILAH/protocol/ipv4.py):
  - `IPv4Packet`: 20-byte base header (`!BBHHHBBH4s4s`), options parsing, payload extraction with Ethernet padding trimming, and header checksum serialization.
  - `checksum`: Reusable RFC 1071 ones' complement 16-bit internet checksum algorithm.
  - Protocol constants: `PROTO_ICMP = 0x01`, `PROTO_TCP = 0x06`, `PROTO_UDP = 0x11`.
- [`protocol/icmp.py`](file:///c:/Users/lenovo/Desktop/SILAH/protocol/icmp.py):
  - `IcmpPacket`: 8-byte header (`!BBHHH`) with whole-message checksum validation and serialization.
  - `build_echo_reply`: Constructs an ICMP Echo Reply exactly mirroring the request's identifier, sequence, and payload data.

---

---

## Part 4: TCP Header Parsing & Pseudo-Header Checksum

Part 4 implements Layer 4 TCP segment serialization, parsing, flag manipulation, variable options decoding, and RFC 793 IPv4 pseudo-header checksum validation.

### Analogy
- **TCP Segment**: The numbered-pages parcel system inside the shipping envelope. Every byte shipped gets a running page number (sequence number), and the receiver confirms how many continuous pages have arrived (acknowledgment number).
- **Flag Bits**: Checkboxes stamped directly on the parcel envelope (`SYN` = start a conversation, `ACK` = acknowledge received bytes, `FIN` = close stream, `RST` = reset, `PSH` = push to application, `URG` = urgent pointer).
- **Pseudo-Header Checksum**: TCP borrowing the delivery address off the outer IPv4 envelope before sealing its tamper-proof checksum seal, preventing packets delivered to the wrong IP address from being accepted silently.

### Key Components
- [`protocol/tcp.py`](file:///c:/Users/lenovo/Desktop/SILAH/protocol/tcp.py):
  - `TcpSegment`: 20-byte base header (`!HHIIHHHH`), dynamic `data_offset` calculation, flag isolation, options carrying, and wire-format serialization.
  - `flags_to_str`: Formats flag bitmasks into canonical strings (e.g. `"SYN|ACK"`).
  - `verify_checksum`: Builds the 12-byte IPv4 pseudo-header and validates segment checksum integrity.
  - Flag constants: `FLAG_FIN (0x01)`, `FLAG_SYN (0x02)`, `FLAG_RST (0x04)`, `FLAG_PSH (0x08)`, `FLAG_ACK (0x10)`, `FLAG_URG (0x20)`.

---

## Verification & Testing

### Tier 1 Automated Tests (No Root / No Kernel Device Required)
Runs anywhere without root privileges to validate:
- `struct ifreq` exact memory packing and flag preservation.
- Hardcoded constants (`TUNSETIFF`, `IFF_TAP`, `IFF_NO_PI`, ARP/IPv4/ICMP/TCP constants).
- Asynchronous reader and FIFO frame ordering through `asyncio.Queue`.
- Synchronous send pipeline and teardown idempotency.
- Ethernet, ARP, IPv4, ICMP, and TCP packet pack/parse round-trips.
- RFC 1071 internet checksum and RFC 793 TCP pseudo-header checksum calculation.
- Independent from-scratch test checksum verification and anti-tamper/anti-misdelivery checks.
- Full end-to-end ping and TCP-over-IPv4 composition pipelines.
- Total absence of OS socket APIs and connection state machine references.

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
