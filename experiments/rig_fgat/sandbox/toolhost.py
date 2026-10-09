#!/usr/bin/env python3
"""Runs one rig tool call inside the sandbox container.

Reads {"op": "tool", "name": ..., "args": {...}} or {"op": "load_progress"} as
JSON on stdin and writes the result as JSON on stdout. The tool functions are
rig's own (rig.py is bind-mounted read-only at /opt/rig/rig.py), so their
behaviour is identical to an unsandboxed run; only where they execute changes.
"""
import json
import os
import sys

os.environ.setdefault("RIG_MODEL", "toolhost")  # rig.py exits without it; no model calls happen here
sys.path.insert(0, "/opt/rig")
import rig  # noqa: E402

req = json.load(sys.stdin)
try:
    if req["op"] == "load_progress":
        out = rig.load_progress()
    else:
        out = rig.TOOLS[req["name"]](**req["args"])
    resp = {"ok": True, "result": out}
except Exception as e:  # rig's loop formats these as "ERROR: <type>: <msg>"
    resp = {"ok": False, "exc_type": type(e).__name__, "exc_msg": str(e)}
sys.stdout.write(json.dumps(resp))
