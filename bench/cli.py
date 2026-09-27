"""Command line entry point: `python -m bench ...`."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .probes import load_cases, run_cases
from .report import scorecard_markdown, summary_markdown
from .scoring import score
from .targets import ROOT, list_targets, load_target

RESULTS_DIR = ROOT / "results"


def _finalize(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload["score"] = score(payload)
    payload["categories"] = _recompute_categories(payload)
    return payload


def _recompute_categories(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    from .probes import SEVERITY_WEIGHT

    buckets: Dict[str, Dict[str, Any]] = {}
    for result in payload.get("results", []):
        bucket = buckets.setdefault(
            result["category"],
            {"pass": 0, "fail": 0, "warn": 0, "not_applicable": 0, "error": 0, "weight_pass": 0, "weight_applicable": 0},
        )
        bucket[result["status"]] = bucket.get(result["status"], 0) + 1
        weight = SEVERITY_WEIGHT.get(result["severity"], 1)
        if result["status"] in {"pass", "fail"}:
            bucket["weight_applicable"] += weight
            if result["status"] == "pass":
                bucket["weight_pass"] += weight
    for bucket in buckets.values():
        bucket["score"] = (
            round(100.0 * bucket["weight_pass"] / bucket["weight_applicable"], 1)
            if bucket["weight_applicable"]
            else None
        )
        bucket["verdict"] = "not_tested" if not bucket["weight_applicable"] else ("pass" if bucket["fail"] == 0 else "fail")
    return buckets


def run_one(name: str, verbose: bool, timestamp: bool = False) -> Dict[str, Any]:
    target = load_target(name)
    run_dir = RESULTS_DIR / target.name
    payload = run_cases(target, run_dir, verbose=verbose)
    payload = _finalize(payload)
    # Scorecards are committed as evidence, so they are deterministic by default:
    # a second run of the same corpus must not produce a diff. Pass --timestamp to
    # record the run time anyway.
    if timestamp:
        payload["generated_at"] = _dt.datetime.now().astimezone().isoformat(timespec="seconds")

    # The target's stderr tail lives in raw-probes.json only: it carries the
    # target's own log timestamps and would otherwise make the scorecard drift.
    card = {key: value for key, value in payload.items() if key != "stderr_tail"}
    (run_dir / "scorecard.json").write_text(
        json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown = scorecard_markdown(payload)
    (run_dir / "scorecard.md").write_text(markdown, encoding="utf-8")

    score_info = payload["score"]
    print(
        f"{target.name:<22} verdict={score_info['verdict']:<13} score={score_info['score']} "
        f"tools={payload.get('tool_count', 0)} findings={score_info['findings_total']}"
    )
    return payload


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bench", description="MCP security benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list targets and cases")

    run_parser = sub.add_parser("run", help="run probes against one or all targets")
    run_parser.add_argument("--target", help="target name or path (default: all)")
    run_parser.add_argument("-v", "--verbose", action="store_true")
    run_parser.add_argument("--timestamp", action="store_true",
                            help="record the run time in the scorecard (off by default, to keep results deterministic)")

    sub.add_parser("summary", help="rebuild results/SUMMARY.md from existing scorecards")
    args = parser.parse_args(argv)

    if args.command == "list":
        print("targets:")
        for target in list_targets():
            print(f"  {target.name:<22} {' '.join(target.command)}   # {target.notes}")
        print("\ncases:")
        for case in load_cases():
            expectation = case.get("expect", case.get("mode", "-"))
            print(f"  {case['id']:<34} {case['category']:<24} {case['severity']:<8} expect={expectation}")
        return 0

    if args.command == "run":
        names = [args.target] if args.target else [target.name for target in list_targets()]
        cards: List[Dict[str, Any]] = []
        for name in names:
            cards.append(run_one(name, args.verbose, args.timestamp))
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "SUMMARY.md").write_text(summary_markdown(cards), encoding="utf-8")
        print(f"\nsummary written to {RESULTS_DIR / 'SUMMARY.md'}")
        return 0

    cards = []
    for path in sorted(RESULTS_DIR.glob("*/scorecard.json")):
        cards.append(json.loads(path.read_text(encoding="utf-8")))
    if not cards:
        print("no scorecards found; run `python -m bench run` first", file=sys.stderr)
        return 1
    (RESULTS_DIR / "SUMMARY.md").write_text(summary_markdown(cards), encoding="utf-8")
    print(f"summary written to {RESULTS_DIR / 'SUMMARY.md'} ({len(cards)} scorecards)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
