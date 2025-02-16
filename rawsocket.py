import os
import struct
import fcntl

class RawSocket:

    BPF_DEVICES_COUNT = 4
    BIOCSETIF = 0x8020426c  # Set interface for BPF
    BIOCIMMEDIATE = 0x80044270  # immediate mode for BPF
    
    def __init__(self, ifname):
        if not isinstance(ifname, bytes):
            ifname = bytes(ifname.encode())
        self.ifname = ifname

    def send(self, frame: bytes):
        # open a bpf device and bind it to network card
        self.bind_bpf()
        # write the frame to the bound BPF device
        try:
            os.write(self.bpf_device, frame)
        except OSError as e:
            print("Packet not sent!\n" + e)
            return 0
        finally:
            if self.bpf_device is not None:
                try:
                    os.close(self.bpf_device)
                except OSError:
                    pass
        return 1

    def send_arp(
            self, *, frame: bytes = bytes(), source_mac: bytes = bytes(), source_ip: bytes = bytes(), target_ip: bytes = bytes()
        ):
        if not len(frame) and len(source_mac + source_ip + target_ip) != 14:
            raise TypeError("Either a frame or other parameters must be provided!")
        if len(frame):
            return self.send(frame)

        # ARP Header Fields
        hw_type = b'\x00\x01'  # Ethernet = 1
        proto_type = b'\x08\x00'  # IPv4
        hw_length = b'\x06'
        proto_length = b'\x04'
        opcode = b'\x00\x01'  # 1 for Request or 2 for Reply
        arp_frame_header = (
            hw_type + proto_type + hw_length + proto_length
            + opcode + source_mac + source_ip + b"\x00" * 6 + target_ip
        )
        frame = RawSocket.frame(b"\xff" * 6, source_mac, ethertype=b"\x08\x06", payload=arp_frame_header) # 0x0806 -> ARP
        return self.send(frame)

    def _open_bpf_device(self):
        for i in range(RawSocket.BPF_DEVICES_COUNT):
            try:
                self.bpf_device = os.open(f"/dev/bpf{i}", os.O_RDWR)
                break
            except FileNotFoundError:
                continue
        if self.bpf_device is None:
            raise Exception("No available BPF device found")

    @staticmethod
    def frame(
        dest_mac: bytes, source_mac: bytes, *, ethertype: bytes = b'\x88\xB5', payload: str | bytes = bytes()
    ):
        if not isinstance(payload, bytes):
            payload = bytes(payload.encode("utf-8"))
        payload_length = len(payload)
        if payload_length < 46:
            # pad payload with zeros to ensure its at least 46 bytes for ethernet packets (layer 2)
            payload = struct.pack(f"{46 if payload_length < 46 else payload_length}s", payload)
        return dest_mac + source_mac +  ethertype + payload # FCS (4 bytes) gets added automatically by the network interface

    def bind_bpf(self):
        self._open_bpf_device()
        ifr = struct.pack("16s", self.ifname) # network interface must be 16 bytes
        # Bind the BPF device to the specified network interface
        fcntl.ioctl(self.bpf_device, RawSocket.BIOCSETIF, ifr)
        # enable immdeiate mode
        self._set_bpf()
    
    def _set_bpf(self):
        immediate_mode = struct.pack("I", 1)
        # enabling BIOCIMMEDIATE ensures packets are processed and sent immediately
        # to ensure packets don't get stuck in buffer.
        fcntl.ioctl(self.bpf_device, RawSocket.BIOCIMMEDIATE, immediate_mode)