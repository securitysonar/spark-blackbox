#!/usr/bin/env python3
"""Beacon sink for the Agentic Black Box trials.

Same JSONL record format as spark-rig-eval's mock_listener.py, but binds
0.0.0.0 inside its own container so the tool sandbox can reach it over the
internal Docker network (bbx-net) and nothing else can.
"""
import http.server
import json
import os
import time

PORT = int(os.environ.get("BBX_LISTENER_PORT", "8898"))
LOG_PATH = os.environ.get("BBX_LISTENER_LOG", "/srv/listener_requests.jsonl")


class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        record = {
            "ts": time.time(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"[bbx_listener] listening on 0.0.0.0:{PORT}, logging to {LOG_PATH}", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
