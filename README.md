# MCP security benchmark (v0.1)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23003715.svg)](https://doi.org/10.5281/zenodo.23003715)

Dataset mirror (probe corpus + all five scorecards): <https://huggingface.co/datasets/CieveHe/mcp-security-benchmark>

A small, dependency-free harness that probes **MCP servers** over stdio and scores them against a
fixed corpus of security-relevant cases: read-only contract violations, dangerous tools registered
by default, SQL whitelist bypasses, credential exposure, prompt-injection surface, and unredacted
output.

It exists because "our MCP server is read-only and safe" is a claim, not evidence. The claim becomes
evidence when a fixed corpus runs against the server, produces a scorecard, and the harness has been
shown to *fail* a deliberately broken server.

```bash
python -m bench list                     # targets + case corpus
python -m bench run                       # run every target, write results/
python -m bench run --target everything-public -v
python -m unittest discover -s tests -v   # classifier unit tests
```

No third-party Python packages are needed for the harness itself (the targets have their own).

## Results (2026-09-28, this machine)

| target | what it is | verdict | score | tools | findings | advisories |
|---|---|---:|---:|---:|---:|---:|
| `vulnerable-demo` | bundled **canary** target, insecure on purpose | critical | 4.8 | 6 | 12 | 0 |
| `everything-public` | npm `@modelcontextprotocol/server-everything` | elevated | 88.0 | 13 | 1 | 0 |
| `mysql-ops-mcp-reference` | read-only-first MySQL ops server (the reference implementation) | no findings | 100.0 | 17 | 0 | 2 |
| `filesystem-public` | npm `@modelcontextprotocol/server-filesystem` | no findings | 100.0 | 14 | 0 | 0 |
| `memory-public` | npm `@modelcontextprotocol/server-memory` | no findings | 100.0 | 9 | 0 | 0 |

The one high finding: `server-everything` exposes a `get-env` tool that returns the **process
environment**; the probe recovered both canary secrets the harness injected. For an agent host that
means any API key in the server's environment is one tool call away.

Detail: `results/SUMMARY.md` and `results/<target>/scorecard.md`. Read the caveats below before
quoting any of these numbers.

## What the score does and does not mean

- `score` = severity-weighted pass rate over **applicable** probes (critical 4 / high 3 / medium 2 /
  low 1). A probe whose tool pattern does not exist on a target is `not_applicable` and moves
  neither way; a probe that could not observe anything (target backend unreachable) is reported as
  `not_applicable` with a "unverifiable" note rather than as a pass.
- **100 is not "secure".** The corpus has 14 cases. It covers a few well-known failure shapes; it
  does not cover authentication, transport, sandboxing, dependency risk, or the target's own
  business logic.
- Name-based registration checks are heuristics. A tool called `deploy_check` may be perfectly
  read-only, so the harness reports such names as **advisories** that do not affect the score
  (`mysql-ops-mcp-reference` carries two of them). A human decides.
- Refusal detection reads the response body, not only `isError`, because several implementations
  (FastMCP included) return refusals as ordinary content with `isError=false`
  (see `docs/harness-notes.md`).
- Comparing a read-only server with a filesystem server is only meaningful per category, since the
  declared policies differ. The per-target scorecards carry that detail.

## Layout

```
bench/            harness: stdio JSON-RPC client, probes, scoring, reporting, CLI
cases/cases.json  the probe corpus (the contract)
targets/*.json    how to launch each server, plus the policy it declares
servers/          the bundled insecure canary target
results/          generated scorecards + SUMMARY.md (committed as evidence)
docs/             threat model, harness notes, methodology limits
sandbox/          scratch directory handed to file-oriented targets
```

## Reproducing

```bash
python -m bench run                       # all targets (npm targets download on first run)
python -m bench run --target vulnerable-demo
python -m bench summary                   # rebuild SUMMARY.md from existing scorecards
```

Requirements: Python ≥ 3.10 and, for the npm targets, Node ≥ 18 with a reachable npm registry
(this machine uses a mirror; set `npm_config_cache` inside the repository, as the target files do,
or npm will want to write outside the sandbox).

The `mysql-ops-mcp-reference` target points at a separate checkout of that project. Point
`MCPBENCH_MYSQL_OPS_DIR` at it (default: `third_party/mysql-ops-mcp`), or skip that target — the other
four need nothing but Python and Node:

```bash
MCPBENCH_MYSQL_OPS_DIR=/path/to/mysql-ops-mcp python -m bench run --target mysql-ops-mcp-reference
```

Scorecards are deterministic: re-running the same corpus produces no diff, so the committed
`results/` files are evidence rather than scratch output. `raw-probes.json` is the exception — it
keeps the target's own stderr tail, which carries the target's log timestamps, and that is the point
of keeping it. Pass `--timestamp` if you want the scorecard to record its run time.

## Redaction policy for committed evidence

The findings are stored in a public repository, so raw target output is never stored verbatim:

- excerpts are limited to the lines that carry the finding (a credential-exposure finding keeps the
  canary match, not the caller's environment);
- absolute paths, secret-shaped values and this machine's identifiers are masked (`<path>`,
  `<secret>`, `<local>`) by `bench/probes.py`, with regression tests in `tests/test_redaction.py`;
- `target_file` is stored relative to the repository root, and target configs use `{root}` /
  `{env:NAME:default}` placeholders instead of absolute paths.

While developing this harness, an early run committed a real environment dump (paths and variable
names from the machine that produced it). The collection layer was fixed, and on 2026-09-28 the
published history was replaced by this redacted history, so the dump is not part of the repository
any more; those commits no longer exist on `main`. That is why the history is short — and it is the
sharpest illustration of the class of mistake this benchmark is about: a probe that reports
credential exposure will faithfully republish the secret unless the collection layer redacts it
before storing it.

## Method in one line

Start the target as a subprocess, complete the MCP handshake, enumerate `tools/list`, then execute
fixed calls and classify each response against an explicit expectation (`reject`, `no_leak`,
`absent`, or a metadata scan). Every scorecard keeps the raw response excerpt for the finding, so
each claim can be checked by hand.
