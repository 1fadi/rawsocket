# RawSocket

## Overview
This repository contains a low level python implementation of a raw socket interface for sending Ethernet frames using Berkeley Packet Filters (BPF) on BSD based systems.

## Prerequisites
Ensure you are running a Unix-based system (e.g., macOS, freeBSD, openBSD etc) that supports BPF devices (`/dev/bpf*`).

## Installation
No additional dependencies are required. This module relies on Python's built-in `os`, `struct`, and `fcntl` modules.
```
python3 -m pip install rawsock
```

## Usage

### Example Code
```python
from rawsock.rawsocket import RawSocket

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
    source_mac="76:c9:1d:f1:27:04",
    source_ip="192.168.178.85",
    target_ip="192.168.178.22"
)
```
#### To receive incoming packets while sending:

```python
sock = RawSocket("en0")
with sock.listener(5): # listen for 5 seconds
    success = sock.send_arp(
        source_mac="76:c9:1d:f1:27:04",
        source_ip="192.168.178.85",
        target_ip="192.168.178.22"
    )
print(sock.captured_packets)
```
#### Apply custom filters to capture specific packets:
```python
# the following code listens for ARP packets with the specified
# dest mac address and checks if the target ip is available in payload
# which means the device has responded with its mac address if its
# connected to the network
with sock.listener(6, filter_ = {"ethertype": b"\x08\x06", "destination_mac": "76:c9:1d:f1:27:04", "payload": [b"\xc0\xa8\xb2\x16",]}):
    success = sock.send_arp(
        source_mac="76:c9:1d:f1:27:04",
        source_ip="192.168.178.85",
        target_ip="192.168.178.22"
    )
print(sock.captured_packets)
```
## Methods
### `send(frame: bytes) -> int`
Sends an Ethernet frame via the bound BPF device. Returns `1` on success, `0` on failure.

### `frame(dest_mac: bytes, source_mac: bytes, ethertype: bytes = b'\x88\xB5', payload: str | bytes) -> bytes`
Constructs an Ethernet frame with the specified parameters.

### `send_arp(...)`
A public method to send an ARP request.

## Notes
- This code has been tested on macOS with **python 3.13**. 
- The code assumes that at least one `/dev/bpf*` device is available and **not busy**.
- Packets may require root privileges to send. (on macOS you must run the script as root)
- Wireshark usually occupies the first found BPF device `/dev/bpf0` if it's open and listening, so make sure to use `/dev/bpf1` in the script.
- The system’s network interface must be in promiscuous mode to receive raw packets.

## License
This code is licensed under the MIT License.
