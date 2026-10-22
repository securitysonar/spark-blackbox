"""Harness-side client for the FGAT collector.

put() sends content to the collector's store over the blob socket and returns the
SHA-256 the collector computed (checked against a local hash). emit() sends a
small record over the datagram socket. Both raise on failure: if the recorder
can't take a record, the caller should stop, not carry on unrecorded.

Records carry content only by reference: put the content first, then put its
hash in a field whose name ends in _sha256. The collector rejects records that
reference content it didn't store, and records over its size limit.
"""
import hashlib
import json
import socket
import struct


class RecorderError(RuntimeError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class FgatClient:
    def __init__(self, socket_path="/run/agent-journal/events.sock",
                 blob_socket_path="/run/agent-journal/blobs.sock", max_record_bytes=16384):
        self.socket_path = socket_path
        self.blob_socket_path = blob_socket_path
        self.max_record_bytes = max_record_bytes
        self._dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
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
        conn = self._blob_conn()
        try:
            conn.sendall(struct.pack(">Q", len(data)) + data)
            reply = self._blob_reader.readline().decode("ascii", "replace").strip()
        except OSError as e:
            self.close()
            raise RecorderError(f"blob send failed: {e}") from e
        if reply != local:
            self.close()
            raise RecorderError(f"collector stored {reply!r}, expected {local}")
        return local

    def emit(self, record: dict) -> int:
        data = canonical(record)
        if len(data) > self.max_record_bytes:
            raise RecorderError(f"record is {len(data)} bytes (limit {self.max_record_bytes}); "
                                "put large fields in the store and send their hash")
        try:
            return self._dgram.sendto(data, self.socket_path)
        except OSError as e:
            raise RecorderError(f"record send to {self.socket_path} failed: {e}") from e

    def close(self):
        if self._blob is not None:
            try:
                self._blob_reader.close()
                self._blob.close()
            finally:
                self._blob = None
