"""Run the probe corpus against a live target and classify the outcome."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .protocol import ProtocolError, StdioMCPClient, flatten_content
from .targets import Target

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "cases" / "cases.json"

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Phrases a well-built server uses when it refuses an operation.
REFUSAL_PATTERNS = re.compile(
    r"(not allowed|not permitted|disallow|denied|deny|refus|forbidden|blocked|read[- ]only|"
    r"readonly|invalid|rejected|unsupported|must not|only [a-z/ ]+ allowed|whitelist|"
    r"outside|no such tool|permission|"
    r"\u5b89\u5168|\u53ea\u8bfb|\u7981\u6b62|\u62d2\u7edd|\u4e0d\u5141\u8bb8|\u4e0d\u5141\u8bb8\u8bbf\u95ee)",
    re.IGNORECASE,
)

# A short, high-confidence refusal marker at the start of a response body.
STRONG_REFUSAL = re.compile(r"(?im)^\s*(error|refused|rejected|denied|blocked)\b|error:")

# "Connection refused" is an outage, not a policy decision: never score it as a refusal.
TRANSPORT_FAILURE = re.compile(
    r"(?i)(connection refused|connection reset|could not connect|unable to connect|"
    r"timed? ?out|timeout|unreachable|no route|unknown host|econnrefused|network is|"
    r"access denied for user|authentication failed|no such host|ssh|paramiko|"
    r"\u8fde\u63a5\u5931\u8d25|\u8d85\u65f6)",
)

MUTATING_TOOL = re.compile(
    r"(write|delete|remove|drop|truncate|update|insert|create|rename|move|chmod|chown|"
    r"kill|restart|deploy|exec|execute|shell|run_|_run|eval|publish|push)",
    re.IGNORECASE,
)

# A mutating-sounding verb followed by a read-only suffix (``deploy_check``,
# ``query_stats``) is name-level ambiguity, not evidence of a violation. The
# benchmark reports those as advisories instead of scoring them.
READ_SUFFIX = re.compile(
    r"(_check|_status|_info|_list|_show|_preview|_validate|_dry_?run|_stats|_logs?|_get|_health)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------- redaction
# Results are committed to a public repository, so raw target output must never be
# stored verbatim: a credential-exposure finding otherwise republishes the very
# environment dump it is reporting. Paths and secret-shaped values are masked, and
# the local machine identifiers are masked by name.
PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\"'\s,}]+|/(?:Users|home)/[^\"'\s,}]+")
SECRET_PATTERN = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    r"|(sk-[A-Za-z0-9]{16,})"
    r"|((?i:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*[^\s,}\"']+)"
)
ENV_ASSIGNMENT = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]{2,})\s*=\s*(.+)$")


def _local_identifiers() -> List[str]:
    """Identifiers of this machine that must not appear in public artifacts."""
    candidates = [
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERDOMAIN", ""),
        os.environ.get("USERNAME", ""),
        os.environ.get("USERPROFILE", ""),
    ]
    # Names shorter than four characters are too likely to appear inside ordinary
    # words ("hz" in "Hz"), and paths are already covered by PATH_PATTERN.
    return [value for value in candidates if len(value) >= 4]


def redact(text: str) -> str:
    if not text:
        return ""
    text = PATH_PATTERN.sub("<path>", text)
    text = SECRET_PATTERN.sub("<secret>", text)
    for identifier in _local_identifiers():
        text = re.sub(re.escape(identifier), "<local>", text, flags=re.IGNORECASE)
    return text


def _excerpt(text: str, findings: List[str]) -> str:
    """Keep only the evidence lines, redacted.

    A finding about an environment dump should carry the canary match, not the
    caller's whole environment.
    """
    lines = text.splitlines()
    tokens = [item for item in findings if not item.startswith("regex:")]
    matched = [line for line in lines if any(token in line for token in tokens)]
    selected = matched or lines[:4]
    joined = " | ".join(line.strip() for line in selected[:6])
    return redact(joined)[:400]


@dataclass
class ProbeResult:
    case_id: str
    category: str
    severity: str
    status: str  # pass | fail | not_applicable | error
    tool: Optional[str]
    detail: str
    response_excerpt: str = ""
    evidence: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "tool": self.tool,
            "detail": self.detail,
            "response_excerpt": self.response_excerpt[:600],
            "evidence": self.evidence or {},
        }


def load_cases(path: Path = CASES_PATH) -> List[Dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def _match_tool(tools: List[Dict[str, Any]], pattern: str) -> Optional[Dict[str, Any]]:
    regex = re.compile(pattern, re.IGNORECASE)
    for tool in tools:
        if regex.search(tool.get("name", "")):
            return tool
    return None


def _argument_payload(case: Dict[str, Any], tool_name: str, run_dir: Path) -> Dict[str, Any]:
    arguments: Dict[str, Any] = {}
    canary = _canary_path()
    for key, value in case.get("arguments", {}).items():
        if isinstance(value, str):
            value = (
                value.replace("{tool}", tool_name)
                .replace("{run_dir}", str(run_dir))
                .replace("{canary_file}", str(canary))
            )
        arguments[key] = value
    return arguments


def _canary_dir() -> Path:
    """An ASCII-only directory outside every target's working scope.

    The repository lives under a path with non-ASCII characters. Passing such a
    path to a target would test the target's stdin/argv encoding rather than its
    access control, so probe payloads only ever use this ASCII temp directory.
    """
    path = Path(tempfile.gettempdir()) / "mcpbench-canary"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _canary_path() -> Path:
    return _canary_dir() / "canary.env"


def _write_canary() -> Path:
    """A secret that only the harness knows, used to detect leaks by content."""
    path = _canary_path()
    path.write_text(
        "# Harness canary: if a server returns this value, it read data outside its scope.\n"
        "MCPBENCH_CANARY_SECRET=mcpbench-canary-3f9a1c2d7e5b\n"
        "AWS_SECRET_ACCESS_KEY=sk-mcpbench-canary-0000deadbeef1111\n",
        encoding="utf-8",
    )
    return path


def _classification(
    case: Dict[str, Any], result: Dict[str, Any], text: str, arguments: Dict[str, Any]
) -> tuple:
    """Return (status, detail) for a tool-call case."""
    expectation = case["expect"]
    transport_error = "transport_error" in result
    tool_error = bool(result.get("isError")) or transport_error
    transport_flavor = bool(TRANSPORT_FAILURE.search(text))
    refusal_language = (bool(REFUSAL_PATTERNS.search(text)) or bool(STRONG_REFUSAL.search(text))) and not transport_flavor
    echoed_payload = any(
        isinstance(value, str) and value and value in text for value in arguments.values()
    )
    detect = case.get("detect", {})

    if expectation == "reject":
        if tool_error:
            suffix = " with a refusal message" if refusal_language else ""
            return "pass", "server rejected the request" + suffix
        # Several MCP implementations (FastMCP among them) return a refusal as
        # ordinary content with isError=false, so the body has to be read too.
        if refusal_language:
            return "pass", "server refused in the response body (isError was not set)"
        dangerous = [item for item in detect.get("forbidden_substrings", []) if item.lower() in text.lower()]
        if dangerous:
            return "fail", f"request succeeded and the response contains {dangerous!r}"
        if detect.get("require_echo"):
            if echoed_payload:
                return "fail", "request succeeded and the payload was echoed back"
            return "pass", "request succeeded but the payload was not echoed"
        return "fail", "request succeeded although it should have been rejected"

    if expectation == "no_leak":
        findings = [item for item in detect.get("forbidden_substrings", []) if item and item in text]
        for pattern in detect.get("forbidden_regex", []):
            if re.search(pattern, text):
                findings.append(f"regex:{pattern}")
        if findings:
            return "fail", f"response leaked {findings!r}"
        if tool_error:
            if refusal_language:
                return "pass", "server refused the request, so nothing could leak"
            return "not_applicable", "call failed for an unrelated reason; this probe observed nothing (unverifiable)"
        return "pass", "response contained none of the forbidden patterns"

    return "error", f"unknown expectation {expectation!r}"


def run_cases(
    target: Target,
    run_dir: Path,
    cases: Optional[List[Dict[str, Any]]] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    cases = cases or load_cases()
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_canary()
    client = StdioMCPClient(
        command=target.command,
        cwd=target.cwd,
        env={**target.env, **target.placeholder_env},
        timeout=target.timeout,
        name=target.name,
    )
    results: List[ProbeResult] = []
    handshake: Dict[str, Any] = {}
    tools: List[Dict[str, Any]] = []

    client.start()
    try:
        try:
            info = client.initialize()
            handshake = {
                "ok": True,
                "protocol_version": client.protocol_version,
                "server_info": client.server_info,
                "raw": info,
            }
        except ProtocolError as exc:
            handshake = {"ok": False, "error": str(exc), "stderr_tail": client.stderr_tail}
            payload = {
                "target": target.name,
                "handshake": handshake,
                "tools": [],
                "results": [],
                "connection_failed": True,
            }
            (run_dir / "raw-probes.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            return payload

        try:
            tools = client.list_tools()
        except ProtocolError as exc:
            handshake["tools_error"] = str(exc)

        for case in cases:
            case_id = case["id"]
            category = case["category"]
            severity = case["severity"]

            if not case.get("mode"):
                if case.get("requires_read_only") and target.declared_read_only is not True:
                    results.append(ProbeResult(case_id, category, severity, "not_applicable", None,
                                               "target does not declare a read-only contract"))
                    continue

                if case.get("requires_no_dangerous_tools") and not target.expect_no_dangerous_tools:
                    results.append(ProbeResult(case_id, category, severity, "not_applicable", None,
                                               "target does not declare dangerous-tool gating"))
                    continue

            if case.get("mode") == "tool_list_scan":
                gate = case.get("gate", "no_dangerous_tools")
                gate_ok = (
                    target.declared_read_only is True
                    if gate == "read_only"
                    else target.expect_no_dangerous_tools
                )
                candidates = [
                    tool["name"]
                    for tool in tools
                    if MUTATING_TOOL.search(tool.get("name", "")) and tool["name"] not in case.get("allow", [])
                ]
                strong = [name for name in candidates if not READ_SUFFIX.search(name)]
                weak = [name for name in candidates if READ_SUFFIX.search(name)]
                if not gate_ok:
                    results.append(
                        ProbeResult(case_id, category, severity, "not_applicable", None,
                                    f"target does not declare the `{gate}` gate")
                    )
                elif strong:
                    results.append(
                        ProbeResult(case_id, category, severity, "fail", None,
                                    f"{len(strong)} mutating tool(s) registered by default",
                                    evidence={"tools": strong, "advisory_tools": weak})
                    )
                elif weak:
                    results.append(
                        ProbeResult(case_id, category, severity, "warn", weak[0],
                                    f"{len(weak)} tool name(s) mention a mutating verb but carry a read-only suffix; "
                                    "needs human confirmation",
                                    evidence={"tools": weak})
                    )
                else:
                    results.append(ProbeResult(case_id, category, severity, "pass", None,
                                               "no mutating tool registered by default"))
                continue

            if case.get("mode") == "metadata_scan":
                patterns = [re.compile(item, re.IGNORECASE) for item in case["detect"]["description_regex"]]
                offenders = []
                for tool in tools:
                    description = tool.get("description") or ""
                    for pattern in patterns:
                        if pattern.search(description):
                            offenders.append({"tool": tool["name"], "pattern": pattern.pattern})
                            break
                if offenders:
                    results.append(
                        ProbeResult(case_id, category, severity, "fail", offenders[0]["tool"],
                                    f"{len(offenders)} tool description(s) contain instructions addressed to the model",
                                    evidence={"offenders": offenders})
                    )
                else:
                    results.append(ProbeResult(case_id, category, severity, "pass", None,
                                               f"scanned {len(tools)} tool description(s), none contains imperative instructions"))
                continue

            pattern = case.get("tool_pattern")
            tool = _match_tool(tools, pattern) if pattern else None
            if case["expect"] == "absent":
                if tool:
                    results.append(ProbeResult(case_id, category, severity, "fail", tool["name"],
                                               "tool is registered although the declared policy forbids it"))
                else:
                    results.append(ProbeResult(case_id, category, severity, "pass", None, "tool is not registered"))
                continue

            if tool is None:
                results.append(ProbeResult(case_id, category, severity, "not_applicable", None,
                                           f"no tool matches /{pattern}/"))
                continue

            arguments = _argument_payload(case, tool["name"], run_dir)
            try:
                response = client.call_tool(tool["name"], arguments)
            except ProtocolError as exc:
                results.append(ProbeResult(case_id, category, severity, "error", tool["name"], f"call failed: {exc}"))
                continue
            text = flatten_content(response)
            status, detail = _classification(case, response, text, arguments)
            excerpt = (
                _excerpt(text, case.get("detect", {}).get("forbidden_substrings", []))
                if status in {"fail", "error"}
                else ""
            )
            results.append(ProbeResult(case_id, category, severity, status, tool["name"], detail, excerpt))
            if verbose:
                print(f"  [{status:>14}] {case_id} -> {tool['name']}: {detail}")
    finally:
        client.stop()

    payload = {
        "target": target.name,
        "target_file": (
            str(target.file.relative_to(ROOT)) if target.file and target.file.is_relative_to(ROOT) else None
        ),
        "notes": target.notes,
        "declared_read_only": target.declared_read_only,
        "expect_no_dangerous_tools": target.expect_no_dangerous_tools,
        "handshake": handshake,
        "protocol_version": client.protocol_version,
        "server_info": client.server_info,
        "stderr_tail": [redact(line) for line in client.stderr_tail],
        "tool_count": len(tools),
        "tools": [
            {
                "name": tool.get("name"),
                "description": redact((tool.get("description") or "")[:400]),
                "annotations": tool.get("annotations", {}),
            }
            for tool in tools
        ],
        "results": [item.as_dict() for item in results],
        "connection_failed": False,
    }
    (run_dir / "raw-probes.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload
