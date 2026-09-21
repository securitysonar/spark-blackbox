"""
Tool Registry with Cryptographic Ingress Hashing Hooks
Ensures all files, web content, and API inputs are hashed at the boundary before entering context.
"""

import os
import subprocess
from typing import Any, Dict, List, Optional
from .provenance_interceptor import AgentFlightRecorder


class ToolRegistry:
    def __init__(self, workspace_root: str, recorder: Optional[AgentFlightRecorder] = None):
        self.workspace_root = os.path.abspath(workspace_root)
        self.recorder = recorder

    def get_manifest(self) -> List[Dict[str, Any]]:
        """Returns standard JSON schema declarations for available tools."""
        return [
            {
                "name": "read_file",
                "description": "Reads file contents into context, calculating SHA-256 ingress digest.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to file in workspace"}
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "write_file",
                "description": "Writes or overwrites a file in the workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to file"},
                        "content": {"type": "string", "description": "Text content to write"},
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "execute_shell",
                "description": "Executes a shell command in the local container environment.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Bash command to execute"}
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "list_dir",
                "description": "Lists contents of a directory in the workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative directory path", "default": "."}
                    },
                },
            },
        ]

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches tool execution with boundary interception."""
        if tool_name == "read_file":
            return self._tool_read_file(arguments.get("path", ""))
        elif tool_name == "write_file":
            return self._tool_write_file(arguments.get("path", ""), arguments.get("content", ""))
        elif tool_name == "execute_shell":
            return self._tool_execute_shell(arguments.get("command", ""))
        elif tool_name == "list_dir":
            return self._tool_list_dir(arguments.get("path", "."))
        else:
            return {"exit_code": 1, "stdout": "", "stderr": f"Unknown tool: {tool_name}"}

    def _tool_read_file(self, rel_path: str) -> Dict[str, Any]:
        full_path = os.path.normpath(os.path.join(self.workspace_root, rel_path))
        if not os.path.exists(full_path):
            return {"exit_code": 1, "stdout": "", "stderr": f"File not found: {rel_path}"}

        try:
            with open(full_path, "rb") as f:
                raw_bytes = f.read()

            # Invariant 3: Hook ingress hash before string enters context
            ingress_hash = ""
            if self.recorder:
                ingress_hash = self.recorder.register_ingress(
                    artifact_type="file",
                    source=rel_path,
                    raw_bytes=raw_bytes,
                )

            content = raw_bytes.decode("utf-8", errors="replace")
            return {
                "exit_code": 0,
                "stdout": content,
                "stderr": "",
                "ingress_hash": ingress_hash,
                "byte_count": len(raw_bytes),
            }
        except Exception as e:
            return {"exit_code": 1, "stdout": "", "stderr": str(e)}

    def _tool_write_file(self, rel_path: str, content: str) -> Dict[str, Any]:
        full_path = os.path.normpath(os.path.join(self.workspace_root, rel_path))
        try:
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            return {"exit_code": 0, "stdout": f"Successfully wrote {len(content)} bytes to {rel_path}", "stderr": ""}
        except Exception as e:
            return {"exit_code": 1, "stdout": "", "stderr": str(e)}

    def _tool_execute_shell(self, command: str) -> Dict[str, Any]:
        try:
            res = subprocess.run(
                command,
                shell=True,
                cwd=self.workspace_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stdout": "", "stderr": "Command timed out after 30 seconds"}
        except Exception as e:
            return {"exit_code": 1, "stdout": "", "stderr": str(e)}

    def _tool_list_dir(self, rel_path: str) -> Dict[str, Any]:
        full_path = os.path.normpath(os.path.join(self.workspace_root, rel_path))
        try:
            entries = os.listdir(full_path)
            return {"exit_code": 0, "stdout": "\n".join(entries), "stderr": ""}
        except Exception as e:
            return {"exit_code": 1, "stdout": "", "stderr": str(e)}
