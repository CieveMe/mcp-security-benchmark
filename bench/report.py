"""Render scorecards as Markdown."""

from __future__ import annotations

from typing import Any, Dict, List

from .scoring import ordered_categories

SEVERITY_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}


def scorecard_markdown(payload: Dict[str, Any]) -> str:
    score = payload["score"]
    lines: List[str] = [
        f"# MCP security scorecard - `{payload['target']}`",
        "",
        f"- generated: {payload.get('generated_at', 'n/a')}",
        f"- protocol version: {payload.get('protocol_version') or 'n/a'}",
        f"- server info: `{payload.get('server_info') or {}}`",
        f"- tools exposed: {payload.get('tool_count', 0)}",
        f"- verdict: **{score['verdict']}**  |  risk score: **{score['score']}** "
        f"(100 = no findings)  |  findings: {score['findings_total']} "
        f"(critical {score['critical_findings']}, high {score['high_findings']})  |  "
        f"advisories: {score.get('advisories', 0)}",
        "",
    ]
    if payload.get("notes"):
        lines += [f"> {payload['notes']}", ""]
    if payload.get("connection_failed"):
        lines += ["**The target could not be initialized; no probe ran.**", ""]
        lines += ["```", str(payload.get("handshake", {}).get("error"))[:500], "```", ""]
        return "\n".join(lines)

    lines += [
        "## Categories",
        "",
        "| category | verdict | score | pass | fail | warn | n/a | error |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ordered_categories(payload["categories"]):
        bucket = payload["categories"][name]
        lines.append(
            f"| {name} | {bucket['verdict']} | {bucket['score'] if bucket['score'] is not None else 'n/a'} | "
            f"{bucket['pass']} | {bucket['fail']} | {bucket.get('warn', 0)} | {bucket['not_applicable']} | {bucket['error']} |"
        )
    lines.append("")

    advisories = [item for item in payload["results"] if item["status"] == "warn"]
    if advisories:
        lines += [
            "## Advisories (not scored)",
            "",
            "These are name-level or environment-level suspicions that the harness cannot settle on its own. "
            "They are listed so a human can confirm or dismiss them, and they deliberately do not move the score.",
            "",
            "| case | tool | detail |",
            "|---|---|---|",
        ]
        for item in advisories:
            lines.append(f"| `{item['case_id']}` | `{item['tool']}` | {item['detail']} |")
        lines.append("")

    findings = [item for item in payload["results"] if item["status"] == "fail"]
    lines += ["## Findings", ""]
    if not findings:
        lines += ["None. Every applicable probe either passed or did not apply to this target.", ""]
    else:
        lines += ["| severity | case | tool | detail |", "|---|---|---|---|"]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for item in sorted(findings, key=lambda value: order.get(value["severity"], 9)):
            lines.append(
                f"| {SEVERITY_MARK.get(item['severity'], item['severity'])} | `{item['case_id']}` | "
                f"`{item['tool']}` | {item['detail']} |"
            )
        lines.append("")
        lines += ["### Evidence", ""]
        for item in sorted(findings, key=lambda value: order.get(value["severity"], 9)):
            excerpt = (item.get("response_excerpt") or "").replace("\n", " ")[:300]
            lines += [f"- `{item['case_id']}` -> `{item['tool']}`: {excerpt}", ""]

    lines += ["## Probe detail", "", "| case | category | severity | status | tool | detail |", "|---|---|---|---|---|---|"]
    for item in payload["results"]:
        lines.append(
            f"| `{item['case_id']}` | {item['category']} | {item['severity']} | {item['status']} | "
            f"`{item['tool']}` | {item['detail']} |"
        )
    lines.append("")
    return "\n".join(lines)


def summary_markdown(scorecards: List[Dict[str, Any]]) -> str:
    lines: List[str] = [
        "# MCP security benchmark - comparison",
        "",
        "`score` = severity-weighted pass rate over *applicable* probes (100 = no findings). "
        "`n/a` probes are probes whose tool pattern does not exist on that target, so they neither "
        "help nor hurt the score.",
        "",
        "| target | verdict | score | tools | findings (crit/high) | read-only | gating | categories failed |",
        "|---|---|---:|---:|---|---|---|---|",
    ]
    for card in scorecards:
        score = card["score"]
        failed = [name for name, bucket in card["categories"].items() if bucket["verdict"] == "fail"]
        lines.append(
            f"| `{card['target']}` | {score['verdict']} | {score['score']} | {card.get('tool_count', 0)} | "
            f"{score['findings_total']} ({score['critical_findings']}/{score['high_findings']}) | "
            f"{card.get('declared_read_only')} | {card.get('expect_no_dangerous_tools')} | "
            f"{', '.join(failed) if failed else '-'} |"
        )
    lines += [
        "",
        "## How to read this",
        "",
        "- A high score is **not** a security audit: the corpus is small, probes are heuristics, and",
        "  `not_applicable` cases hide surface the corpus does not know how to reach.",
        "- Comparing servers with different declared policies is only meaningful for the categories",
        "  they both expose; the per-target scorecards carry the detail.",
        "- The `vulnerable-demo` target exists to prove the harness can fail: any run where it scores",
        "  well means the harness is broken, not that the demo is safe.",
        "",
    ]
    return "\n".join(lines)
