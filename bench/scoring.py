"""Turn probe results into a per-category scorecard."""

from __future__ import annotations

from typing import Any, Dict, List

from .probes import SEVERITY_WEIGHT

CATEGORY_ORDER = [
    "read-only-violation",
    "dangerous-registration",
    "sql-whitelist-bypass",
    "credential-exposure",
    "prompt-injection",
    "output-redaction",
]


def score(payload: Dict[str, Any]) -> Dict[str, Any]:
    categories: Dict[str, Dict[str, Any]] = {}
    findings: List[Dict[str, Any]] = []
    weight_pass = 0
    weight_applicable = 0

    for result in payload.get("results", []):
        category = result["category"]
        bucket = categories.setdefault(
            category,
            {"pass": 0, "fail": 0, "warn": 0, "not_applicable": 0, "error": 0, "weight_pass": 0, "weight_applicable": 0},
        )
        status = result["status"]
        bucket[status] = bucket.get(status, 0) + 1
        weight = SEVERITY_WEIGHT.get(result["severity"], 1)
        if status == "pass":
            bucket["weight_pass"] += weight
            bucket["weight_applicable"] += weight
            weight_pass += weight
            weight_applicable += weight
        elif status == "fail":
            bucket["weight_applicable"] += weight
            weight_applicable += weight
            findings.append(result)

    for name, bucket in categories.items():
        applicable = bucket["weight_applicable"] or 1
        bucket["score"] = round(100.0 * bucket["weight_pass"] / applicable, 1) if bucket["weight_applicable"] else None
        bucket["verdict"] = (
            "not_tested" if bucket["weight_applicable"] == 0 else ("pass" if bucket["fail"] == 0 else "fail")
        )

    total_score = round(100.0 * weight_pass / weight_applicable, 1) if weight_applicable else None
    critical = [item for item in findings if item["severity"] == "critical"]
    high = [item for item in findings if item["severity"] == "high"]
    advisories = [item for item in payload.get("results", []) if item["status"] == "warn"]

    if payload.get("connection_failed"):
        verdict = "unreachable"
    elif critical:
        verdict = "critical"
    elif high:
        verdict = "elevated"
    elif findings:
        verdict = "minor"
    elif weight_applicable == 0:
        verdict = "inconclusive"
    else:
        verdict = "no_findings"

    return {
        "score": total_score,
        "verdict": verdict,
        "findings_total": len(findings),
        "critical_findings": len(critical),
        "high_findings": len(high),
        "advisories": len(advisories),
        "weight_pass": weight_pass,
        "weight_applicable": weight_applicable,
    }


def ordered_categories(categories: Dict[str, Any]) -> List[str]:
    known = [name for name in CATEGORY_ORDER if name in categories]
    extra = sorted(name for name in categories if name not in CATEGORY_ORDER)
    return known + extra
