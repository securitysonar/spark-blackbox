#!/usr/bin/env python3
"""
Forensic Telemetry Collector Daemon
Runs under an isolated service user (e.g., svc-audit-collector) on the DGX Spark host.
Listens on an append-only UNIX domain socket, cryptographically chains turns, and dispatches to dual planes:
  1. Operational Plane (lightweight JSON for SIEM/SOAR/Vector ingestion)
  2. Evidentiary Plane (tamper-evident WORM archive with SHA-256 block chaining)
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Support importing PcapWriter if available
try:
    from wireshark.pcap_writer import PcapWriter
except ImportError:
    try:
        from pcap_writer import PcapWriter
    except ImportError:
        PcapWriter = None


class ForensicCollector:
    def __init__(
        self,
        socket_path: str = "/run/agent-journal/events.sock",
        operational_path: str = "/var/log/agent-operational/events.jsonl",
        worm_path: str = "/var/log/agent-worm/audit_journal.jsonl",
        udp_mirror: Optional[str] = None,
        pcap_path: Optional[str] = None,
        allow_uids: Optional[set] = None,
        rejects_path: Optional[str] = None,
    ):
        self.socket_path = socket_path
        self.operational_path = operational_path
        self.worm_path = worm_path
        self.udp_mirror = udp_mirror
        self.pcap_path = pcap_path
        # Senders are authenticated by the UID the kernel attaches to each datagram
        # (SO_PASSCRED / SCM_CREDENTIALS), not by anything in the payload. Only the
        # harness UID belongs here; tool sandboxes must run under a different UID.
        self.allow_uids = set(allow_uids) if allow_uids else {os.getuid()}
        self.rejects_path = rejects_path or os.path.join(os.path.dirname(worm_path), "rejected.jsonl")
        self.last_block_hash = "0" * 64  # Genesis block initialization
        self.running = False
        self.sock = None
        self.udp_sock = None
        self.pcap_writer = None

        if self.udp_mirror:
            host, port_str = self.udp_mirror.split(":")
            self.udp_target = (host, int(port_str))
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.udp_target = None

        if self.pcap_path:
            if PcapWriter is None:
                print("[-] WARNING: PcapWriter module unavailable. PCAP output disabled.")
            else:
                Path(self.pcap_path).parent.mkdir(parents=True, exist_ok=True)
                self.pcap_writer = PcapWriter(self.pcap_path)

    def _init_storage(self):
        Path(self.operational_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.worm_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.rejects_path).parent.mkdir(parents=True, exist_ok=True)

        # Resume last block hash if journal already exists
        if os.path.exists(self.worm_path) and os.path.getsize(self.worm_path) > 0:
            with open(self.worm_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            record = json.loads(line)
                            if "_chain" in record and "block_hash" in record["_chain"]:
                                self.last_block_hash = record["_chain"]["block_hash"]
                        except Exception:
                            pass

    def start(self):
        self._init_storage()

        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.socket_path)
        # Owner and group only. The UID check below is the real control; the mode
        # keeps other local users from reaching the socket at all.
        os.chmod(self.socket_path, 0o660)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        except OSError:
            pass

        self.running = True

        def _sig_handler(sig, frame):
            print("\n[*] Stopping forensic collector daemon...")
            self.running = False

        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, _sig_handler)
                signal.signal(signal.SIGTERM, _sig_handler)
            except (ValueError, AttributeError):
                pass

        print(f"[*] Forensic Collector listening on: {self.socket_path}")
        print(f"[*] Operational stream target:     {self.operational_path}")
        print(f"[*] Evidentiary WORM target:       {self.worm_path}")
        print(f"[*] Initial block hash:            {self.last_block_hash[:16]}...")
        print(f"[*] Accepted sender UIDs:          {sorted(self.allow_uids)}")

        with open(self.worm_path, "a", buffering=1, encoding="utf-8") as worm_f, \
             open(self.operational_path, "a", buffering=1, encoding="utf-8") as op_f, \
             open(self.rejects_path, "a", buffering=1, encoding="utf-8") as rej_f:

            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    data, ancdata, _, _ = self.sock.recvmsg(65535, socket.CMSG_SPACE(UCRED.size))
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[-] Socket read error: {e}", file=sys.stderr)
                    break

                if not data:
                    continue

                ingest_ts = datetime.now(timezone.utc).isoformat()
                cred = sender_credentials(ancdata)
                if cred is None or cred["uid"] not in self.allow_uids:
                    # Not chained. Kept as evidence of the attempt.
                    rej = {"host_ingest_utc": ingest_ts, "sender": cred,
                           "reason": "no credentials" if cred is None else "sender uid not allowed",
                           "payload_sha256": hashlib.sha256(data).hexdigest(),
                           "payload_bytes": len(data)}
                    rej_f.write(canonical(rej).decode("utf-8") + "\n")
                    print(f"[-] Rejected datagram from {cred}: {rej['reason']}", file=sys.stderr)
                    continue

                try:
                    record = json.loads(data.decode("utf-8"))
                    if not isinstance(record, dict):
                        raise ValueError("record is not a JSON object")
                except Exception as e:
                    print(f"[-] Malformed payload discarded: {e}", file=sys.stderr)
                    continue

                # The collector, not the sender, sets these fields.
                record.pop("_chain", None)
                record["_ingest"] = {"host_ingest_utc": ingest_ts, "sender_uid": cred["uid"],
                                     "sender_pid": cred["pid"], "sender_gid": cred["gid"]}

                # 1. Chain: SHA-256(H_{n-1} || canonical JSON of the record incl. _ingest).
                #    verify_journal recomputes this from the stored line.
                current_block_hash = block_hash(self.last_block_hash, record)
                record["_chain"] = {
                    "prev_hash": self.last_block_hash,
                    "block_hash": current_block_hash,
                }

                # 2. Write to Evidentiary Plane (Complete provenance + chain)
                worm_f.write(canonical(record).decode("utf-8") + "\n")
                self.last_block_hash = current_block_hash

                # 3. Write to Operational Plane (Lightweight structured JSON event)
                operational_event = {
                    "session_id": record.get("session_id"),
                    "turn_id": record.get("turn_id"),
                    "timestamp_utc": record.get("timestamp_utc"),
                    "tool_name": record.get("proposed_action", {}).get("name"),
                    "gate_verdict": record.get("gate_verdict", {}).get("status"),
                    "rule_id": record.get("gate_verdict", {}).get("rule_id"),
                    "exit_code": record.get("execution_result", {}).get("exit_code"),
                    "host_ingest_utc": ingest_ts,
                    "sender_uid": cred["uid"],
                    # The operational plane is shipped off-host; its block_hash sequence
                    # is the external anchor that verify_journal --anchor checks against.
                    "block_hash": current_block_hash,
                }
                op_f.write(json.dumps(operational_event) + "\n")

                # 4. Mirror full 10-tuple over UDP if configured (e.g. for Wireshark live capture)
                full_turn_bytes = json.dumps(record).encode("utf-8")
                if self.udp_sock and self.udp_target:
                    try:
                        self.udp_sock.sendto(full_turn_bytes, self.udp_target)
                    except Exception as e:
                        print(f"[-] UDP mirror error: {e}", file=sys.stderr)

                # 5. Record frame to PCAP file if configured
                if self.pcap_writer:
                    try:
                        dst_port = self.udp_target[1] if self.udp_target else 9999
                        self.pcap_writer.write_udp_packet(
                            full_turn_bytes,
                            src_port=54321,
                            dst_port=dst_port,
                        )
                    except Exception as e:
                        print(f"[-] PCAP write error: {e}", file=sys.stderr)

        if self.pcap_writer:
            self.pcap_writer.close()

        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except OSError:
                pass
        print("[*] Collector daemon shutdown complete.")


def verify_journal(worm_path: str, anchor_path: Optional[str] = None) -> bool:
    """Recompute every block hash and check the linkage; optionally check the chain
    against the operational plane's block_hash sequence (the external anchor).

    Without the anchor, someone who can rewrite the whole file can recompute a
    consistent chain. The anchor catches that, as long as it lives somewhere the
    same person cannot also rewrite.
    """
    if not os.path.exists(worm_path):
        print(f"[-] File not found: {worm_path}", file=sys.stderr)
        return False

    last_hash = "0" * 64
    hashes = []

    with open(worm_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception as e:
                print(f"[-] Line {idx + 1}: JSON decode error: {e}")
                return False

            chain = record.pop("_chain", {})
            if chain.get("prev_hash") != last_hash:
                print(f"[-] Line {idx + 1}: Broken linkage! Expected prev_hash {last_hash}, "
                      f"found {chain.get('prev_hash')}")
                return False
            computed = block_hash(last_hash, record)
            if computed != chain.get("block_hash"):
                print(f"[-] Line {idx + 1}: Hash mismatch! Stored block_hash {chain.get('block_hash')}, "
                      f"recomputed {computed}. The record was altered after it was chained.")
                return False
            last_hash = computed
            hashes.append(computed)

    print(f"[+] Recomputed and verified {len(hashes)} blocks in {worm_path}. Head: {last_hash}")

    if anchor_path:
        anchored = []
        with open(anchor_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    anchored.append(json.loads(line).get("block_hash"))
        if anchored != hashes:
            n = next((i for i, (a, b) in enumerate(zip(anchored, hashes)) if a != b),
                     min(len(anchored), len(hashes)))
            print(f"[-] Anchor mismatch at block {n + 1}: journal has {len(hashes)} blocks, "
                  f"anchor {anchor_path} has {len(anchored)}; sequences differ.")
            return False
        print(f"[+] Chain matches the external anchor ({len(anchored)} block hashes in {anchor_path}).")
    return True


UCRED = struct.Struct("3i")  # struct ucred: pid_t pid, uid_t uid, gid_t gid


def sender_credentials(ancdata) -> Optional[dict]:
    for level, ctype, cdata in ancdata:
        if level == socket.SOL_SOCKET and ctype == socket.SCM_CREDENTIALS and len(cdata) >= UCRED.size:
            pid, uid, gid = UCRED.unpack(cdata[:UCRED.size])
            return {"pid": pid, "uid": uid, "gid": gid}
    return None


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def block_hash(prev_hash: str, record: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(canonical(record))
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Forensic-Grade Agent Telemetry Collector Daemon")
    parser.add_argument("--socket", default=os.getenv("FGAT_SOCKET", "/run/agent-journal/events.sock"),
                        help="Path to UNIX domain socket")
    parser.add_argument("--operational", default=os.getenv("FGAT_OPERATIONAL", "/var/log/agent-operational/events.jsonl"),
                        help="Path to operational JSONL stream")
    parser.add_argument("--worm", default=os.getenv("FGAT_WORM", "/var/log/agent-worm/audit_journal.jsonl"),
                        help="Path to evidentiary WORM archive")
    parser.add_argument("--udp-mirror", default=os.getenv("FGAT_UDP_MIRROR", None),
                        help="Mirror full 10-tuple turns over UDP (e.g. 127.0.0.1:9999 for Wireshark)")
    parser.add_argument("--pcap", default=os.getenv("FGAT_PCAP", None),
                        help="Path to write standard libpcap .pcap file for Wireshark analysis")
    parser.add_argument("--allow-uid", type=int, action="append",
                        default=[int(u) for u in os.getenv("FGAT_ALLOW_UIDS", "").split(",") if u],
                        help="Sender UID to accept (repeatable). Default: the collector's own UID")
    parser.add_argument("--rejects", default=os.getenv("FGAT_REJECTS", None),
                        help="Where rejected datagrams are logged (not chained)")
    parser.add_argument("--verify", action="store_true", help="Verify cryptographic chain integrity of target WORM file")
    parser.add_argument("--anchor", default=None,
                        help="With --verify: operational-plane file whose block_hash sequence must match the journal")

    args = parser.parse_args()

    if args.verify:
        sys.exit(0 if verify_journal(args.worm, args.anchor) else 1)
    else:
        collector = ForensicCollector(
            socket_path=args.socket,
            operational_path=args.operational,
            worm_path=args.worm,
            udp_mirror=args.udp_mirror,
            pcap_path=args.pcap,
            allow_uids=set(args.allow_uid) or None,
            rejects_path=args.rejects,
        )
        collector.start()


if __name__ == "__main__":
    main()
