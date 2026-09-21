"""
Multi-Turn Agent Runner
Executes autonomous task loops with pluggable models (OpenAI/vLLM/Nemotron or deterministic Mock).
Demonstrates context compaction and coordinates turn-level provenance recording.
"""

import argparse
import os
import sys
import uuid
from typing import Any, Dict, List, Optional
from .provenance_interceptor import AgentFlightRecorder
from .intercepted_tools import ToolRegistry


class AgentRunner:
    def __init__(
        self,
        session_id: Optional[str] = None,
        workspace_dir: str = "./workspace",
        model_name: str = "nemotron-3-super",
        recorder: Optional[AgentFlightRecorder] = None,
        compaction_threshold_turns: int = 5,
    ):
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"
        self.workspace_dir = workspace_dir
        self.model_name = model_name
        self.recorder = recorder
        self.compaction_threshold_turns = compaction_threshold_turns

        self.tools = ToolRegistry(self.workspace_dir, recorder=self.recorder)
        self.system_prompt = (
            "You are an autonomous engineering assistant. Inspect the repository, "
            "verify internal architecture guidelines, audit configurations, and report status."
        )
        self.history: List[Dict[str, Any]] = []
        self.turn_count = 0

    def compact_context(self) -> Dict[str, Any]:
        """Simulates automated context compaction threshold trigger."""
        earlier_turns = len(self.history)
        compacted_summary = (
            f"Automated compaction pass: Summarized {earlier_turns} turns. "
            "Reviewed repo architecture and internal documentation. Verified Python imports. "
            "Conducting environment checks per architecture guidelines prior to final test reporting."
        )
        delta = {
            "compacted": True,
            "pruned_turn_count": earlier_turns,
            "new_working_memory": compacted_summary,
        }
        # Reset history to compacted representation
        self.history = [{"role": "system", "content": compacted_summary}]
        return delta

    def step(
        self,
        proposed_action: Dict[str, Any],
        gate_verdict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Executes a single turn of the agent loop with telemetry emission."""
        self.turn_count += 1
        tool_name = proposed_action.get("name")
        tool_args = proposed_action.get("parameters", {})

        # Check if compaction triggers before this turn
        context_delta = {
            "compacted": False,
            "active_prompt": f"Executing turn {self.turn_count}",
            "role": "model",
        }
        if self.turn_count >= self.compaction_threshold_turns and len(self.history) > 2:
            context_delta = self.compact_context()

        # Execute intercepted tool
        execution_result = self.tools.execute(tool_name, tool_args)

        # Update internal conversational history
        self.history.append({
            "turn": self.turn_count,
            "action": proposed_action,
            "result": execution_result,
        })

        # Emit Provenance Tuple if recorder is active
        if self.recorder:
            self.recorder.emit_turn(
                turn_id=self.turn_count,
                model_metadata={
                    "name": self.model_name,
                    "provider": "nvidia-dgx-spark-local",
                    "temperature": 0.2,
                },
                system_prompt=self.system_prompt,
                context_delta=context_delta,
                tool_manifest=self.tools.get_manifest(),
                proposed_action=proposed_action,
                gate_verdict=gate_verdict,
                execution_result=execution_result,
            )

        return execution_result
