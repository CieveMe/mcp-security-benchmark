"""Minimal MCP stdio client (JSON-RPC 2.0, newline-delimited).

Deliberately dependency-free: the benchmark must run against a target without
installing the target's SDK, so the protocol is implemented directly and kept
small enough to audit.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")


class ProtocolError(RuntimeError):
    pass


class StdioMCPClient:
    """Start a target MCP server as a subprocess and talk to it over stdio."""

    def __init__(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        name: str = "target",
    ) -> None:
        self.command = command
        self.name = name
        self.timeout = timeout
        merged = dict(os.environ)
        if env:
            merged.update(env)
        self._env = merged
        self._cwd = str(cwd) if cwd else None
        self._process: Optional[subprocess.Popen] = None
        self._next_id = 1
        self._stderr_lines: List[str] = []
        self._inbox: "queue.Queue[Optional[str]]" = queue.Queue()
        self.notifications: List[Dict[str, Any]] = []
        self.protocol_version: Optional[str] = None
        self.server_info: Dict[str, Any] = {}

    # ---------------------------------------------------------------- process
    def start(self) -> None:
        executable = shutil.which(self.command[0])
        if executable is None and not Path(self.command[0]).exists():
            raise ProtocolError(f"executable not found: {self.command[0]}")
        resolved = [executable or self.command[0], *self.command[1:]]
        self._process = subprocess.Popen(
            resolved,
            cwd=self._cwd,
            env=self._env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        threading.Thread(target=self._drain_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stdout(self) -> None:
        """Read stdout in a thread so that request timeouts can actually fire.

        A blocking ``readline()`` on a quiet pipe ignores any deadline; reading
        here and waiting on a queue turns a hung target into a timeout instead of
        a hang. ``None`` marks EOF.
        """
        assert self._process and self._process.stdout
        for line in self._process.stdout:
            self._inbox.put(line)
        self._inbox.put(None)

    def _drain_stderr(self) -> None:
        assert self._process and self._process.stderr
        for line in self._process.stderr:
            self._stderr_lines.append(line.rstrip("\n"))

    def stop(self) -> None:
        if not self._process:
            return
        try:
            if self._process.stdin:
                self._process.stdin.close()
        except Exception:
            pass
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()

    # -------------------------------------------------------------- transport
    def _send(self, payload: Dict[str, Any]) -> None:
        assert self._process and self._process.stdin
        self._process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._process.stdin.flush()

    def _read_message(self, deadline: float) -> Dict[str, Any]:
        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            try:
                line = self._inbox.get(timeout=remaining)
            except queue.Empty:
                raise ProtocolError(
                    f"timeout after {self.timeout:.0f}s waiting for a response; stderr tail: "
                    + " | ".join(self._stderr_lines[-5:])
                )
            if line is None:
                code = self._process.returncode if self._process else "unknown"
                raise ProtocolError(
                    f"target closed stdout (exit code {code}); stderr tail: "
                    + " | ".join(self._stderr_lines[-5:])
                )
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                # Servers that print logs on stdout break the framing; keep the
                # evidence instead of crashing.
                self.notifications.append({"type": "non_json_stdout", "raw": line[:500]})
                continue
            if isinstance(message, dict) and "id" in message:
                return message
            self.notifications.append(message if isinstance(message, dict) else {"raw": message})
        raise ProtocolError(f"timeout after {self.timeout:.0f}s waiting for a response")

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)
        deadline = time.time() + self.timeout
        while True:
            message = self._read_message(deadline)
            if message.get("id") == request_id:
                return message

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

    # ------------------------------------------------------------------ MCP
    def initialize(self, protocol_versions: tuple = DEFAULT_PROTOCOL_VERSIONS) -> Dict[str, Any]:
        last_error: Optional[Exception] = None
        for version in protocol_versions:
            try:
                response = self.request(
                    "initialize",
                    {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-security-benchmark", "version": "0.1.0"},
                    },
                )
            except ProtocolError as exc:
                last_error = exc
                continue
            if "error" in response:
                last_error = ProtocolError(f"initialize rejected for {version}: {response['error']}")
                continue
            result = response.get("result", {})
            self.protocol_version = result.get("protocolVersion", version)
            self.server_info = result.get("serverInfo", {})
            self.notify("notifications/initialized")
            return result
        raise ProtocolError(f"initialize failed for all protocol versions: {last_error}")

    def list_tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(20):
            params = {"cursor": cursor} if cursor else {}
            response = self.request("tools/list", params)
            if "error" in response:
                raise ProtocolError(f"tools/list failed: {response['error']}")
            result = response.get("result", {})
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        response = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in response:
            return {"transport_error": response["error"]}
        return response.get("result", {})

    def list_resources(self) -> List[Dict[str, Any]]:
        try:
            response = self.request("resources/list", {})
        except ProtocolError:
            return []
        if "error" in response:
            return []
        return response.get("result", {}).get("resources", [])

    @property
    def stderr_tail(self) -> List[str]:
        return self._stderr_lines[-20:]


def flatten_content(result: Dict[str, Any]) -> str:
    """Turn an MCP tool result into a single string for pattern matching."""
    if "transport_error" in result:
        return json.dumps(result["transport_error"], ensure_ascii=False)
    parts: List[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                if "text" in item:
                    parts.append(str(item["text"]))
                elif "json" in item:
                    parts.append(json.dumps(item["json"], ensure_ascii=False))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False))
    elif content is not None:
        parts.append(json.dumps(content, ensure_ascii=False))
    for key in ("structuredContent", "isError"):
        if key in result:
            parts.append(f"{key}={json.dumps(result[key], ensure_ascii=False)}")
    return "\n".join(parts)
