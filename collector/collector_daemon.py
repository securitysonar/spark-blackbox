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
import re
import selectors
import signal
import socket
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ForensicCollector:
    def __init__(
        self,
        socket_path: str = "/run/agent-journal/events.sock",
        operational_path: str = "/var/log/agent-operational/events.jsonl",
        worm_path: str = "/var/log/agent-worm/audit_journal.jsonl",
        udp_mirror: Optional[str] = None,
        allow_uids: Optional[set] = None,
        rejects_path: Optional[str] = None,
        store_dir: Optional[str] = None,
        blob_socket_path: Optional[str] = None,
        records_socket_path: Optional[str] = None,
        max_record_bytes: int = 16384,
        max_blob_bytes: int = 64 * 1024 * 1024,
    ):
        self.socket_path = socket_path
        self.operational_path = operational_path
        self.worm_path = worm_path
        # The UDP mirror carries the operational event only: the same line written to
        # the operational file, so a capture of it is a second off-host copy of the
        # anchor. Record content and provenance stay on the evidentiary plane.
        # Captures come from tcpdump, not from the collector.
        self.udp_mirror = udp_mirror
        # Senders are authenticated by the UID the kernel attaches to each datagram
        # (SO_PASSCRED / SCM_CREDENTIALS), not by anything in the payload. Only the
        # harness UID belongs here; tool sandboxes must run under a different UID.
        self.allow_uids = set(allow_uids) if allow_uids else {os.getuid()}
        self.rejects_path = rejects_path or os.path.join(os.path.dirname(worm_path), "rejected.jsonl")
        # Content-addressed store owned by the collector. Records carry only SHA-256
        # references (keys ending in _sha256); the content itself arrives on the blob
        # socket, is hashed here, and is stored under that hash. A record may only
        # reference content this collector stored, and it must stay small.
        self.store_dir = store_dir or os.path.join(os.path.dirname(worm_path), "store")
        self.blob_socket_path = blob_socket_path or os.path.join(os.path.dirname(socket_path), "blobs.sock")
        self.records_socket_path = records_socket_path or os.path.join(os.path.dirname(socket_path), "records.sock")
        self.rec_sock = None
        # Partial writes land here and are renamed into the store, so the store
        # directory itself can be append-only (chattr +a forbids renaming or
        # deleting entries in it, but not creating them).
        self.incoming_dir = self.store_dir.rstrip("/") + ".incoming"
        self.max_record_bytes = max_record_bytes
        self.max_blob_bytes = max_blob_bytes
        self.blob_sock = None
        self._rej_lock = threading.Lock()
        self.rej_f = None
        self.last_block_hash = "0" * 64  # Genesis block initialization
        self.running = False
        self.sock = None
        self.udp_sock = None

        if self.udp_mirror:
            host, port_str = self.udp_mirror.split(":")
            self.udp_target = (host, int(port_str))
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.udp_target = None

    def _init_storage(self):
        Path(self.operational_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.worm_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.rejects_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.store_dir).mkdir(parents=True, exist_ok=True)
        Path(self.incoming_dir).mkdir(parents=True, exist_ok=True)

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

        # Legacy datagram socket: records are chained, but the sender gets no reply.
        # Kept for senders that don't use fgat_client (and for the H6/H7 tests).
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
        self.sock.setblocking(False)

        # Acknowledged records: one SOCK_SEQPACKET connection per client. Each record
        # gets a reply on its connection: "OK <payload sha256> <block_hash>" once it is
        # chained, or "ERR <payload sha256> <reason>". Every connection has its own
        # buffers, so a client that stops reading replies stalls only itself: the
        # collector stops reading from that connection until the reply goes out.
        if os.path.exists(self.records_socket_path):
            os.remove(self.records_socket_path)
        self.rec_sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.rec_sock.bind(self.records_socket_path)
        os.chmod(self.records_socket_path, 0o660)
        self.rec_sock.listen(16)
        self.rec_sock.setblocking(False)

        if os.path.exists(self.blob_socket_path):
            os.remove(self.blob_socket_path)
        self.blob_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.blob_sock.bind(self.blob_socket_path)
        os.chmod(self.blob_socket_path, 0o660)
        self.blob_sock.listen(8)
        self.blob_sock.settimeout(1.0)

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

        print(f"[*] Forensic Collector listening on: {self.records_socket_path} (acknowledged)")
        print(f"[*] Legacy datagram socket:        {self.socket_path} (no replies)")
        print(f"[*] Operational stream target:     {self.operational_path}")
        print(f"[*] Evidentiary WORM target:       {self.worm_path}")
        print(f"[*] Initial block hash:            {self.last_block_hash[:16]}...")
        print(f"[*] Accepted sender UIDs:          {sorted(self.allow_uids)}")
        print(f"[*] Content store:                 {self.store_dir} (blob socket {self.blob_socket_path})")
        print(f"[*] Max record bytes:              {self.max_record_bytes}")

        self.rej_f = open(self.rejects_path, "a", buffering=1, encoding="utf-8")
        blob_thread = threading.Thread(target=self._serve_blobs, daemon=True)
        blob_thread.start()

        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ, ("dgram", None))
        sel.register(self.rec_sock, selectors.EVENT_READ, ("listen", None))
        # Per connection: [sender credentials, pending reply bytes or None]
        conns = {}

        with open(self.worm_path, "a", buffering=1, encoding="utf-8") as worm_f, \
             open(self.operational_path, "a", buffering=1, encoding="utf-8") as op_f:
            self._worm_f, self._op_f = worm_f, op_f

            while self.running:
                for key, events in sel.select(timeout=1.0):
                    kind, _ = key.data
                    if kind == "dgram":
                        self._read_datagrams()
                    elif kind == "listen":
                        self._accept(sel, conns)
                    elif events & selectors.EVENT_WRITE:
                        self._flush_reply(sel, conns, key.fileobj)
                    else:
                        self._read_record(sel, conns, key.fileobj)

        for conn in list(conns):
            sel.unregister(conn)
            conn.close()
        sel.close()
        self.rec_sock.close()
        blob_thread.join(timeout=5)
        self.rej_f.close()
        for path in (self.socket_path, self.records_socket_path, self.blob_socket_path):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        print("[*] Collector daemon shutdown complete.")

    def _read_datagrams(self):
        while True:
            try:
                # Read past the record limit so oversize records are measured, not cut
                # off; MSG_TRUNC flags anything longer than even this buffer.
                data, ancdata, msg_flags, _ = self.sock.recvmsg(RECV_BUFFER, socket.CMSG_SPACE(UCRED.size))
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                if self.running:
                    print(f"[-] Socket read error: {e}", file=sys.stderr)
                return
            if data:
                self._process(data, sender_credentials(ancdata), bool(msg_flags & socket.MSG_TRUNC), "record")

    def _accept(self, sel, conns):
        try:
            conn, _ = self.rec_sock.accept()
        except (BlockingIOError, InterruptedError):
            return
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size)
        pid, uid, gid = UCRED.unpack(raw)
        conn.setblocking(False)
        conns[conn] = [{"pid": pid, "uid": uid, "gid": gid}, None]
        sel.register(conn, selectors.EVENT_READ, ("conn", None))

    def _read_record(self, sel, conns, conn):
        try:
            data, _, msg_flags, _ = conn.recvmsg(RECV_BUFFER)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            sel.unregister(conn)
            del conns[conn]
            conn.close()
            return
        ok, digest, detail = self._process(data, conns[conn][0], bool(msg_flags & socket.MSG_TRUNC), "record-ack")
        reply = f"{'OK' if ok else 'ERR'} {digest} {detail}".encode("utf-8")[:4096]
        try:
            conn.send(reply)
        except (BlockingIOError, InterruptedError):
            # The client isn't reading its replies. Hold this one and stop reading
            # from the connection until it can be sent.
            conns[conn][1] = reply
            sel.modify(conn, selectors.EVENT_WRITE, ("conn", None))
        except OSError:
            sel.unregister(conn)
            del conns[conn]
            conn.close()

    def _flush_reply(self, sel, conns, conn):
        try:
            conn.send(conns[conn][1])
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            sel.unregister(conn)
            del conns[conn]
            conn.close()
            return
        conns[conn][1] = None
        sel.modify(conn, selectors.EVENT_READ, ("conn", None))

    def _process(self, data, cred, truncated, channel):
        """Validate, chain, and dispatch one record. Returns (ok, payload sha256,
        block_hash or rejection reason)."""
        ingest_ts = datetime.now(timezone.utc).isoformat()
        digest = hashlib.sha256(data).hexdigest()
        if cred is None or cred["uid"] not in self.allow_uids:
            # Not chained. Kept as evidence of the attempt.
            reason = "no credentials" if cred is None else "sender uid not allowed"
            self._reject(ingest_ts, cred, reason, data, channel=channel)
            return False, digest, reason
        if truncated or len(data) > self.max_record_bytes:
            size = f"over {RECV_BUFFER}" if truncated else str(len(data))
            reason = (f"record of {size} bytes exceeds {self.max_record_bytes} "
                      "(put content in the store and send its hash)")
            self._reject(ingest_ts, cred, reason, data, channel=channel)
            return False, digest, reason

        try:
            record = json.loads(data.decode("utf-8"))
            if not isinstance(record, dict):
                raise ValueError("record is not a JSON object")
        except Exception as e:
            reason = f"malformed record: {e}"
            self._reject(ingest_ts, cred, reason, data, channel=channel)
            return False, digest, reason

        missing = [h for _, h in content_refs(record) if not self._stored(h)]
        if missing:
            reason = f"references content not in the store: {missing}"
            self._reject(ingest_ts, cred, reason, data, channel=channel)
            return False, digest, reason

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
        self._worm_f.write(canonical(record).decode("utf-8") + "\n")
        self.last_block_hash = current_block_hash

        # 3. Write to Operational Plane (Lightweight structured JSON event)
        # The operational plane is shipped off-host; its block_hash sequence
        # is the external anchor that verify_journal --anchor checks against.
        operational_event = operational_view(record)
        operational_event.update({"host_ingest_utc": ingest_ts, "sender_uid": cred["uid"],
                                  "block_hash": current_block_hash})
        op_line = json.dumps(operational_event)
        self._op_f.write(op_line + "\n")

        # 4. Mirror the operational event (not the record) over UDP if configured.
        if self.udp_sock and self.udp_target:
            try:
                self.udp_sock.sendto(op_line.encode("utf-8"), self.udp_target)
            except Exception as e:
                print(f"[-] UDP mirror error: {e}", file=sys.stderr)
        return True, digest, current_block_hash

    def _reject(self, ingest_ts, cred, reason, data, channel):
        rej = {"host_ingest_utc": ingest_ts, "channel": channel, "sender": cred, "reason": reason,
               "payload_sha256": hashlib.sha256(data).hexdigest(), "payload_bytes": len(data)}
        with self._rej_lock:
            self.rej_f.write(canonical(rej).decode("utf-8") + "\n")
        print(f"[-] Rejected {channel} from {cred}: {reason}", file=sys.stderr)

    def _stored(self, digest: str) -> bool:
        return os.path.exists(os.path.join(self.store_dir, digest))

    def _serve_blobs(self):
        """Blob protocol, per connection: repeat [8-byte big-endian length][bytes];
        the reply to each blob is its 64-hex SHA-256 and a newline, or a line
        starting with ERR. The collector computes the hash; the client checks it."""
        while self.running:
            try:
                conn, _ = self.blob_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_blob_conn, args=(conn,), daemon=True).start()
        self.blob_sock.close()

    def _handle_blob_conn(self, conn):
        with conn:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size)
            pid, uid, gid = UCRED.unpack(raw)
            cred = {"pid": pid, "uid": uid, "gid": gid}
            ts = datetime.now(timezone.utc).isoformat()
            if uid not in self.allow_uids:
                self._reject(ts, cred, "sender uid not allowed", b"", channel="blob-connect")
                return
            conn.settimeout(30)
            while True:
                header = _recv_exact(conn, 8)
                if header is None:
                    return
                n = struct.unpack(">Q", header)[0]
                if n > self.max_blob_bytes:
                    self._reject(datetime.now(timezone.utc).isoformat(), cred,
                                 f"blob of {n} bytes exceeds {self.max_blob_bytes}", b"", channel="blob")
                    conn.sendall(b"ERR too large\n")
                    return
                body = _recv_exact(conn, n)
                if body is None:
                    return
                digest = hashlib.sha256(body).hexdigest()
                path = os.path.join(self.store_dir, digest)
                if not os.path.exists(path):
                    tmp = os.path.join(self.incoming_dir, f"{digest}.{threading.get_ident()}")
                    with open(tmp, "wb") as f:
                        f.write(body)
                        f.flush()
                        os.fsync(f.fileno())
                    os.chmod(tmp, 0o440)
                    os.replace(tmp, path)
                conn.sendall(digest.encode("ascii") + b"\n")


def verify_journal(worm_path: str, anchor_path: Optional[str] = None,
                   store_dir: Optional[str] = None) -> bool:
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
            if store_dir:
                for key, ref in content_refs(record):
                    p = os.path.join(store_dir, ref)
                    if not os.path.exists(p):
                        print(f"[-] Line {idx + 1}: {key} {ref} is missing from the store.")
                        return False
                    with open(p, "rb") as bf:
                        actual = hashlib.sha256(bf.read()).hexdigest()
                    if actual != ref:
                        print(f"[-] Line {idx + 1}: store object {ref} ({key}) now hashes to {actual}. "
                              "The stored content was altered.")
                        return False

    print(f"[+] Recomputed and verified {len(hashes)} blocks in {worm_path}. Head: {last_hash}")
    if store_dir:
        print(f"[+] Every content reference resolves to an unaltered object in {store_dir}.")

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
RECV_BUFFER = 262144
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def content_refs(obj, prefix=""):
    """(key, sha256) for every store reference in a record: keys ending in _sha256,
    at any depth, whose value is a 64-hex digest. _chain and _ingest are skipped."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("_chain", "_ingest"):
                continue
            if k.endswith("_sha256") and isinstance(v, str) and _HEX64.match(v):
                out.append((prefix + k, v))
            else:
                out.extend(content_refs(v, prefix + k + "."))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(content_refs(v, f"{prefix}{i}."))
    return out


# Operational fields per record kind (schema: collector/SCHEMA.md). Metadata only:
# no tool arguments, model text, or content hashes leave the evidentiary plane.
OPERATIONAL_FIELDS = {
    "model_turn": ("trimmed", "payload_in_window", "canary_in_window", "doc_in_window", "latency_s"),
    "intent": ("tool", "classify", "branch", "allowed"),
    "result": ("tool", "result_bytes"),
}


def operational_view(record: dict) -> dict:
    """The operational event for a record, in the Volume 2 event schema. Volume 1
    per-turn records (proposed_action / gate_verdict / execution_result) are mapped
    onto the same names with kind "v1_turn"."""
    if "proposed_action" in record and "kind" not in record:
        pa = record.get("proposed_action") or {}
        gv = record.get("gate_verdict") or {}
        er = record.get("execution_result") or {}
        return {"session_id": record.get("session_id"), "seq": None, "kind": "v1_turn",
                "turn": record.get("turn_id"), "ts": record.get("timestamp_utc"),
                "tool": pa.get("name"), "classify": gv.get("status"), "rule_id": gv.get("rule_id"),
                "exit_code": er.get("exit_code")}
    kind = record.get("kind")
    ev = {"session_id": record.get("session_id"), "seq": record.get("seq"), "kind": kind,
          "turn": record.get("turn"), "ts": record.get("ts")}
    for k in OPERATIONAL_FIELDS.get(kind, ()):
        ev[k] = record.get(k)
    if kind == "model_turn":
        ev["tool_calls"] = [c.get("name") for c in record.get("tool_calls") or [] if isinstance(c, dict)]
    return ev


def _recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


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
                        help="Mirror each operational event over UDP (e.g. 127.0.0.1:9999). "
                             "Capture it with tcpdump: tcpdump -i lo -nn -s0 -U -w FILE udp port 9999")
    parser.add_argument("--pcap", default=os.getenv("FGAT_PCAP", None), help=argparse.SUPPRESS)
    parser.add_argument("--allow-uid", type=int, action="append",
                        default=[int(u) for u in os.getenv("FGAT_ALLOW_UIDS", "").split(",") if u],
                        help="Sender UID to accept (repeatable). Default: the collector's own UID")
    parser.add_argument("--rejects", default=os.getenv("FGAT_REJECTS", None),
                        help="Where rejected datagrams are logged (not chained)")
    parser.add_argument("--verify", action="store_true", help="Verify cryptographic chain integrity of target WORM file")
    parser.add_argument("--anchor", default=None,
                        help="With --verify: operational-plane file whose block_hash sequence must match the journal")
    parser.add_argument("--store", default=os.getenv("FGAT_STORE", None),
                        help="Content-addressed store directory (default: <worm dir>/store). "
                             "With --verify: also check every content reference against it")
    parser.add_argument("--records-socket", default=os.getenv("FGAT_RECORDS_SOCKET", None),
                        help="UNIX seqpacket socket for acknowledged records (default: records.sock next to --socket)")
    parser.add_argument("--blob-socket", default=os.getenv("FGAT_BLOB_SOCKET", None),
                        help="UNIX stream socket for content (default: blobs.sock next to --socket)")
    parser.add_argument("--max-record-bytes", type=int, default=16384,
                        help="Reject records larger than this; content belongs in the store")

    args = parser.parse_args()
    if args.pcap:
        parser.error("--pcap was removed: frames the collector writes itself are not a capture. "
                     "Use --udp-mirror and capture with tcpdump -i lo -nn -s0 -U -w FILE udp port 9999")

    if args.verify:
        sys.exit(0 if verify_journal(args.worm, args.anchor, args.store) else 1)
    else:
        collector = ForensicCollector(
            socket_path=args.socket,
            operational_path=args.operational,
            worm_path=args.worm,
            udp_mirror=args.udp_mirror,
            allow_uids=set(args.allow_uid) or None,
            rejects_path=args.rejects,
            store_dir=args.store,
            blob_socket_path=args.blob_socket,
            records_socket_path=args.records_socket,
            max_record_bytes=args.max_record_bytes,
        )
        collector.start()


if __name__ == "__main__":
    main()
