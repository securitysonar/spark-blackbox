"""
Pure-Python Libpcap File Writer
Generates standard .pcap files containing Ethernet/IPv4/UDP packets
without requiring root privileges, libpcap, or external C dependencies.
"""

import struct
import time
from typing import Optional


class PcapWriter:
    def __init__(self, filename: str, snaplen: int = 65535):
        self.filename = filename
        self.snaplen = snaplen
        self.file = None
        self._write_global_header()

    def _write_global_header(self):
        """Writes 24-byte libpcap global header."""
        # Magic: 0xa1b2c3d4 (little-endian standard pcap)
        # Version: 2.4
        # Thiszone: 0
        # Sigfigs: 0
        # Snaplen: 65535
        # LinkType: 1 (LINKTYPE_ETHERNET)
        self.file = open(self.filename, "wb")
        header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, self.snaplen, 1)
        self.file.write(header)
        self.file.flush()

    def write_udp_packet(
        self,
        payload: bytes,
        timestamp: Optional[float] = None,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 54321,
        dst_port: int = 9999,
    ):
        """Constructs an Ethernet + IPv4 + UDP packet frame and writes it to the pcap."""
        if timestamp is None:
            timestamp = time.time()

        # 1. Ethernet Header (14 bytes)
        # Destination MAC: 00:00:00:00:00:00, Source MAC: 00:00:00:00:00:00
        # Ethertype: 0x0800 (IPv4)
        eth_hdr = b"\x00" * 12 + b"\x08\x00"

        # 2. IPv4 Header (20 bytes)
        ip_total_len = 20 + 8 + len(payload)
        src_ip_bytes = bytes(map(int, src_ip.split(".")))
        dst_ip_bytes = bytes(map(int, dst_ip.split(".")))

        # Version (4) + IHL (5) = 0x45
        # DSCP/ECN = 0, Identification = 54321, Flags/Frag = 0
        # TTL = 64, Protocol = 17 (UDP), Checksum = 0 (placeholder)
        ip_hdr_no_checksum = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 54321, 0, 64, 17, 0,
            src_ip_bytes, dst_ip_bytes
        )

        # Calculate IP Header Checksum
        checksum = 0
        for i in range(0, 20, 2):
            word = (ip_hdr_no_checksum[i] << 8) + ip_hdr_no_checksum[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF

        ip_hdr = ip_hdr_no_checksum[:10] + struct.pack("!H", checksum) + ip_hdr_no_checksum[12:]

        # 3. UDP Header (8 bytes)
        # Source Port, Destination Port, Length (header + payload), Checksum (0 = optional in IPv4)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)

        # 4. Assemble Full Frame
        frame = eth_hdr + ip_hdr + udp_hdr + payload
        captured_len = min(len(frame), self.snaplen)

        # 5. Libpcap Packet Header (16 bytes)
        # ts_sec, ts_usec, incl_len, orig_len
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1_000_000)
        pkt_hdr = struct.pack("<IIII", sec, usec, captured_len, len(frame))

        self.file.write(pkt_hdr + frame[:captured_len])
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
