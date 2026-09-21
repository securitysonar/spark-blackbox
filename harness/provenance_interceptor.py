"""
Agent Flight Recorder & Provenance Interceptor Middleware
Captures the 10-field Decision-Turn Provenance Tuple and enforces Invariant 2 & 3.
"""

import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AgentFlightRecorder:
    def __init__(
        self,
        session_id: str,
        socket_path: str = "/run/agent-journal/events.sock",
        fail_closed: bool = True,
    ):
        self.session_id = session_id
        self.socket_path = socket_path
        self.fail_closed = fail_closed
        self.active_ingress_hashes: List[Dict[str, Any]] = []

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def register_ingress(
        self,
        artifact_type: str,
        source: str,
        raw_bytes: bytes,
    ) -> str:
        """Computes SHA-256 digest of ingested artifact and records it for the active turn."""
        sha256_digest = hashlib.sha256(raw_bytes).hexdigest()
        entry = {
            "type": artifact_type,
            "source": source,
            "sha256": sha256_digest,
            "byte_count": len(raw_bytes),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        self.active_ingress_hashes.append(entry)
        return sha256_digest

    def emit_turn(
        self,
        turn_id: int,
        model_metadata: Dict[str, Any],
        system_prompt: str,
        context_delta: Dict[str, Any],
        tool_manifest: List[Dict[str, Any]],
        proposed_action: Dict[str, Any],
        gate_verdict: Dict[str, Any],
        execution_result: Dict[str, Any],
        state_delta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Assembles and transmits the standardized 10-field Provenance Tuple."""
        # 1. Hashes of instructions and declared capabilities
        sys_hasher = hashlib.sha256()
        sys_hasher.update(system_prompt.encode("utf-8"))
        system_prompt_hash = sys_hasher.hexdigest()

        manifest_str = json.dumps(tool_manifest, sort_keys=True)
        manifest_hasher = hashlib.sha256()
        manifest_hasher.update(manifest_str.encode("utf-8"))
        tool_manifest_hash = manifest_hasher.hexdigest()

        # State delta hash (if tracking local files/env mutation)
        state_hash = None
        if state_delta:
            state_str = json.dumps(state_delta, sort_keys=True)
            state_hash = hashlib.sha256(state_str.encode("utf-8")).hexdigest()

        # Assemble the 10-field tuple
        provenance_tuple = {
            "session_id": self.session_id,
            "turn_id": turn_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "model_metadata": model_metadata,
            "system_prompt_hash": system_prompt_hash,
            "context_delta": context_delta,
            "ingress_hashes": list(self.active_ingress_hashes),
            "tool_manifest_hash": tool_manifest_hash,
            "proposed_action": proposed_action,
            "gate_verdict": gate_verdict,
            "execution_result": execution_result,
            "state_delta_hash": state_hash,
        }

        # Clear active ingress hashes for next turn
        self.active_ingress_hashes.clear()

        # Transmit out-of-band over UNIX domain socket
        serialized = json.dumps(provenance_tuple).encode("utf-8")
        try:
            self.sock.sendto(serialized, self.socket_path)
        except Exception as e:
            msg = f"CRITICAL: Flight recorder socket transmission failed ({self.socket_path}): {e}"
            if self.fail_closed:
                raise SystemError(msg)
            else:
                print(f"[-] WARNING: {msg}")

        return provenance_tuple
