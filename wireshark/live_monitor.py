#!/usr/bin/env python3
"""
Live FGAT Wireshark Telemetry Monitor
Captures mirrored UDP telemetry datagrams (e.g. from collector_daemon.py)
and streams them directly into tshark in real time without requiring
root/sudo privileges or BPF device access (/dev/bpf*).
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
    parser.add_argument(
        "--save",
        default=None,
        help="Optional path to simultaneously record captured stream into a .pcap file",
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
        print("    Install it via: brew install wireshark", file=sys.stderr)
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

    # 5. Initialize PcapWriter for stdin stream (and optional save file)
    stdin_writer = PcapWriter(tshark_proc.stdin)
    file_writer = PcapWriter(args.save) if args.save else None

    print(f"[*] FGAT Live Monitor listening on UDP {host}:{port}")
    print(f"[*] Dissector: {DISSECTOR_LUA}")
    if args.filter:
        print(f"[*] Active Display Filter: {args.filter}")
    if args.save:
        print(f"[*] Saving capture to: {args.save}")
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
        if file_writer:
            file_writer.close()
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

            # Mirror to pcap file if enabled
            if file_writer:
                file_writer.write_udp_packet(
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
