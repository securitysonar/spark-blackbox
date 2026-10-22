#!/usr/bin/env python3
"""
Live FGAT Wireshark Telemetry Monitor
Receives the collector's UDP operational mirror on a socket and streams it
into tshark in real time, without root or BPF access.

This is a viewer, not a capture: it receives payloads, so tshark sees frames
pcap_writer.py builds around them (real source address and port, but invented
Ethernet/IP headers and receive-time timestamps). For a capture you can keep as
evidence, run tcpdump: tcpdump -i lo -nn -s0 -U -w FILE udp port 9999
"""

import argparse
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wireshark.pcap_writer import PcapWriter

DISSECTOR_LUA = REPO_ROOT / "wireshark" / "fgat_dissector.lua"


def main():
    parser = argparse.ArgumentParser(
        description="Stream live FGAT agent telemetry over UDP into tshark in real time."
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1:9999",
        help="Host and UDP port to listen on (default: 127.0.0.1:9999)",
    )
    parser.add_argument(
        "-V", "--verbose",
        action="store_true",
        help="Output full verbose 5-section dissection trees for each packet",
    )
    parser.add_argument(
        "-Y", "--filter",
        default=None,
        help="Wireshark display filter to apply (e.g. 'fgat.turn_id == 5' or '_ws.expert.group == \"Security\"')",
    )

    args = parser.parse_args()

    host, port_str = args.bind.split(":")
    port = int(port_str)

    # 1. Build tshark command
    tshark_cmd = [
        "tshark",
        "-X", f"lua_script:{DISSECTOR_LUA}",
        "-r", "-",  # Read libpcap stream from stdin
        "-l",       # Unbuffered line output
    ]
    if args.verbose:
        tshark_cmd.append("-V")
    if args.filter:
        tshark_cmd.extend(["-Y", args.filter])

    # 2. Check tshark availability
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except Exception:
        print("[-] Error: 'tshark' is not installed or not in PATH.", file=sys.stderr)
        print("    Install it via: apt install tshark (Linux) or brew install wireshark (macOS)", file=sys.stderr)
        sys.exit(1)

    # 3. Create UDP listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except Exception as e:
        print(f"[-] Failed to bind UDP socket to {host}:{port}: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Spawn tshark process
    tshark_proc = subprocess.Popen(
        tshark_cmd,
        stdin=subprocess.PIPE,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    # 5. Initialize PcapWriter for the stdin stream (display only; see docstring)
    stdin_writer = PcapWriter(tshark_proc.stdin)

    print(f"[*] FGAT Live Monitor listening on UDP {host}:{port}")
    print(f"[*] Dissector: {DISSECTOR_LUA}")
    if args.filter:
        print(f"[*] Active Display Filter: {args.filter}")
    print("[*] Waiting for agent telemetry packets (Press Ctrl+C to stop)...")
    print("-" * 75)

    def shutdown(sig, frame):
        print("\n[*] Stopping live monitor...")
        sock.close()
        try:
            tshark_proc.stdin.close()
            tshark_proc.wait(timeout=2)
        except Exception:
            tshark_proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    pkt_count = 0
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            if not data:
                break
            pkt_count += 1

            # Feed to tshark stdin pipe (encapsulate with dst_port=9999 for dissector binding)
            stdin_writer.write_udp_packet(
                payload=data,
                src_ip=addr[0],
                dst_ip=host,
                src_port=addr[1],
                dst_port=9999,
            )
        except (socket.error, BrokenPipeError):
            break
        except Exception as e:
            print(f"[-] Error processing frame: {e}", file=sys.stderr)

    shutdown(None, None)


if __name__ == "__main__":
    main()
