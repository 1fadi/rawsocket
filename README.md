# RawSocket

## Overview
This repository contains a low level python implementation of a raw socket interface for sending Ethernet frames using Berkeley Packet Filters (BPF) on BSD based systems.

## Prerequisites
Ensure you are running a Unix-based system (e.g., macOS, freeBSD, openBSD etc) that supports BPF devices (`/dev/bpf*`).

## Installation
No additional dependencies are required. This module relies on Python's built-in `os`, `struct`, and `fcntl` modules.

## Usage

### Example Code
```python
from rawsocket import RawSocket

# Create a RawSocket instance for network interface 'en0'
sock = RawSocket(b"en0")

# Construct an Ethernet frame with a broadcast destination MAC
frame = RawSocket.frame(
    b'\xff\xff\xff\xff\xff\xff',  # Destination MAC (broadcast)
    b'\x6e\x87\x88\x4d\x99\x5f',  # Source MAC
    ethertype=b"\x88\xB5",
    payload=b"test"  # Custom payload
)

# Send the frame
success = sock.send(frame)

# to send an ARP request:
success = sock.send_arp(
    source_mac=b"\x76\xc9\x1d\xf1\x27\x04",
    source_ip=b"\xc0\xa8\xb2\x01", # # 192.168.178.1
    target_ip=b"\xc0\xa8\xb2\x53" # 192.168.178.53
)
```

## Methods
### `RawSocket(ifname: bytes)`
Initializes the raw socket with the specified network interface.

### `send(frame: bytes) -> int`
Sends an Ethernet frame via the bound BPF device. Returns `1` on success, `0` on failure.

### `frame(dest_mac: bytes, source_mac: bytes, ethertype: bytes = b'\x88\xB5', payload: str | bytes) -> bytes`
Constructs an Ethernet frame with the specified parameters.

### `send_arp(...)`
A public method to send an ARP request.

## Notes
- The code assumes that at least one `/dev/bpf*` device is available and **not busy**.
- Packets may require root privileges to send. (on macOS you must run the script as root)
- Wireshark usually occupies the first found BPF device `/dev/bpf0` if it's open and listening, so make sure to use `/dev/bpf1` in the script.
- The system’s network interface must be in promiscuous mode to receive raw packets.

## License
This code is licensed under the MIT License.
