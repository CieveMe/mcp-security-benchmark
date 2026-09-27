"""Target definitions: how to launch a server and what policy it declares."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT / "targets"

# Target files are part of a public repository, so they must not contain absolute
# paths from the machine that ran them. Two placeholders are supported:
#   {root}          -> this repository's root directory
#   {env:NAME:...}  -> the value of NAME, or a default (applied after {root})
PLACEHOLDER = re.compile(r"\{root\}|\{env:([A-Za-z_][A-Za-z0-9_]*)(?::([^{}]*))?\}")


def expand(value: str) -> str:
    def replace(match: "re.Match[str]") -> str:
        if match.group(0) == "{root}":
            return str(ROOT)
        name, default = match.group(1), match.group(2)
        return os.environ.get(name, default or "")

    # Two passes: {root} first, so an {env:...} default may contain it.
    return PLACEHOLDER.sub(replace, PLACEHOLDER.sub(replace, value))


@dataclass
class Target:
    name: str
    command: List[str]
    cwd: Optional[Path] = None
    env: Dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    declared_read_only: Optional[bool] = None
    expect_no_dangerous_tools: bool = False
    notes: str = ""
    file: Optional[Path] = None

    @property
    def placeholder_env(self) -> Dict[str, str]:
        """Extra env the harness injects so probes can look for obvious leaks."""
        return {
            "MCPBENCH_CANARY_SECRET": "mcpbench-canary-3f9a1c2d7e5b",
            "MCPBENCH_CANARY_TOKEN": "sk-mcpbench-canary-0000deadbeef1111",
        }


def load_target(path_or_name: str) -> Target:
    path = Path(path_or_name)
    if not path.exists():
        candidate = TARGETS_DIR / f"{path_or_name}.json"
        if not candidate.exists():
            raise SystemExit(f"target not found: {path_or_name} (looked at {candidate})")
        path = candidate
    payload = json.loads(path.read_text(encoding="utf-8"))
    cwd = payload.get("cwd")
    return Target(
        name=payload["name"],
        command=[expand(item) for item in payload["command"]],
        cwd=Path(expand(cwd)) if cwd else ROOT,
        env={key: expand(str(item)) for key, item in payload.get("env", {}).items()},
        timeout=float(payload.get("timeout", 30.0)),
        declared_read_only=payload.get("declared_read_only"),
        expect_no_dangerous_tools=bool(payload.get("expect_no_dangerous_tools", False)),
        notes=payload.get("notes", ""),
        file=path,
    )


def list_targets() -> List[Target]:
    return [load_target(item) for item in sorted(TARGETS_DIR.glob("*.json"))]
