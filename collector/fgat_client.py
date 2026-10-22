"""Harness-side client for the FGAT collector.

put() sends content to the collector's store over the blob socket and returns the
SHA-256 the collector computed (checked against a local hash). emit() sends a
small record over the datagram socket and waits for the collector's verdict:
it returns the record's block_hash once the record is chained, and raises if
the collector rejected it or didn't answer in time. Both raise on failure: if
the recorder can't take a record, the caller should stop, not carry on
unrecorded. For an intent record, that means the tool doesn't run.

Records go over one SOCK_SEQPACKET connection to the collector's records
socket, and each reply comes back on the same connection, so nothing else can
answer for the collector. A reply counts only if it names the SHA-256 of the
record just sent. After a timeout the connection is dropped, since a late reply
could otherwise be read as the answer to the next record. A timeout means
"unknown", not "rejected": the collector may still chain the record later.

Records carry content only by reference: put the content first, then put its
hash in a field whose name ends in _sha256. The collector rejects records that
reference content it didn't store, and records over its size limit.
"""
import hashlib
import json
import os
import socket
import struct


class RecorderError(RuntimeError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class FgatClient:
    def __init__(self, socket_path="/run/agent-journal/events.sock",
                 blob_socket_path=None, max_record_bytes=16384, ack_timeout=5.0,
                 records_socket_path=None):
        # socket_path is the collector's legacy datagram socket; the records and
        # blob sockets default to the same directory.
        sock_dir = os.path.dirname(socket_path)
        self.socket_path = socket_path
        self.records_socket_path = records_socket_path or os.path.join(sock_dir, "records.sock")
        self.blob_socket_path = blob_socket_path or os.path.join(sock_dir, "blobs.sock")
        self.max_record_bytes = max_record_bytes
        self.ack_timeout = ack_timeout
        self._rec = None
        self._blob = None

    def _blob_conn(self):
        if self._blob is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(30)
            try:
                s.connect(self.blob_socket_path)
            except OSError as e:
                raise RecorderError(f"blob socket {self.blob_socket_path}: {e}") from e
            self._blob = s
            self._blob_reader = s.makefile("rb")
        return self._blob

    def put(self, content) -> str:
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        local = hashlib.sha256(data).hexdigest()
        # One retry on a fresh connection if the old one was closed: the store is
        # content-addressed, so sending the same bytes twice stores one object.
        for attempt in (1, 2):
            conn = self._blob_conn()
            try:
                conn.sendall(struct.pack(">Q", len(data)) + data)
                reply = self._blob_reader.readline().decode("ascii", "replace").strip()
            except OSError as e:
                self._close_blob()
                if attempt == 2:
                    raise RecorderError(f"blob send failed: {e}") from e
                continue
            if reply or attempt == 2:
                break
            self._close_blob()  # empty reply: the collector closed the connection
        if reply != local:
            self._close_blob()
            raise RecorderError(f"collector stored {reply!r}, expected {local}")
        return local

    def emit(self, record: dict) -> str:
        """Send a record; return its block_hash once the collector has chained it."""
        data = canonical(record)
        if len(data) > self.max_record_bytes:
            raise RecorderError(f"record is {len(data)} bytes (limit {self.max_record_bytes}); "
                                "put large fields in the store and send their hash")
        digest = hashlib.sha256(data).hexdigest()
        if self._rec is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                s.connect(self.records_socket_path)
            except OSError as e:
                s.close()
                raise RecorderError(f"records socket {self.records_socket_path}: {e}") from e
            self._rec = s
        self._rec.settimeout(self.ack_timeout)
        try:
            self._rec.send(data)
            reply = self._rec.recv(4096)
        except socket.timeout:
            self._close_rec()
            raise RecorderError(f"no reply from the collector within {self.ack_timeout}s for record "
                                f"{digest[:16]}...; it may or may not be recorded, so treat it as not")
        except OSError as e:
            self._close_rec()
            raise RecorderError(f"record send failed: {e}") from e
        if not reply:
            self._close_rec()
            raise RecorderError("collector closed the connection without replying")
        status, _, rest = reply.decode("utf-8", "replace").partition(" ")
        got, _, detail = rest.partition(" ")
        if got != digest:
            self._close_rec()
            raise RecorderError(f"reply names record {got[:16]}..., expected {digest[:16]}...")
        if status == "OK":
            return detail
        raise RecorderError(f"collector rejected the record: {detail}")

    def _close_rec(self):
        if self._rec is not None:
            try:
                self._rec.close()
            finally:
                self._rec = None

    def close(self):
        self._close_rec()
        self._close_blob()

    def _close_blob(self):
        if self._blob is not None:
            try:
                self._blob_reader.close()
                self._blob.close()
            finally:
                self._blob = None
