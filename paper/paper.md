---
title: "Do MCP servers keep their read-only promises? A probe corpus and scorecards for agent-facing tool servers"
authors:
  - name: Zhen He
    orcid: 0009-0009-1526-5793
    affiliation: Independent Researcher
date: 2026-09-28
status: draft (not submitted)
---

# Abstract

Model Context Protocol (MCP) servers expose databases, file systems and infrastructure to language-model
agents. Operators routinely describe such servers as "read-only", but that description usually lives in
a README rather than in an auditable contract, and nothing in the protocol enforces it. We present a
small, dependency-free benchmark: six failure categories, fourteen probes, a stdio JSON-RPC harness and a
severity-weighted scorecard. The harness was validated against a deliberately insecure server that must
fail: it scores 4.8/100 with twelve findings. Across five servers the corpus produced one high-severity
finding — an official demo server whose `get-env` tool returns the process environment, from which the
probe recovered both canary secrets it had injected — which we reported upstream. The three remaining
servers scored without findings, and we are explicit that a score of 100 is not a security claim: the
corpus is fourteen cases, and absence of a finding is not absence of a vulnerability. We also record
three defects the benchmark found **in itself**, each of which would have produced a wrong verdict,
because those failures are the same shapes any MCP client hits.

# 1. Introduction

An MCP server is a process that advertises *tools* to a client — typically an agent — over JSON-RPC.
The agent calls what `tools/list` returns; it cannot see what the operator intended. This creates a
class of failure that is not a classic vulnerability: the server is working as designed, the design
just does not match the promise made about it. A server can be described as "read-only" while
registering a tool that restarts a container, and an agent that is asked to "check the status of the
backend" has no way to know that one of the available tools is destructive.

The claim we care about is therefore auditability: **which policy was in force, and how would anyone
else check?** A hand-written script that a researcher ran once cannot answer that question. A fixed
corpus, a scorecard and a deliberately broken control can.

Our contributions are:

1. A threat model of six categories for agent-facing tool servers, each expressed as probes that
   require no destructive action (Section 3).
2. A dependency-free stdio JSON-RPC harness with an explicit applicability rule, an advisory channel
   for name-based heuristics, and a severity-weighted score (Section 4).
3. Scorecards for five servers plus a control that must fail, and one upstream-reported finding
   (Section 5).
4. Three defects the harness found in itself, with the rule each one changed (Section 6).

We deliberately do not claim novelty for the underlying ideas. Least privilege, allowlists and
single-statement validation are old. The contribution is the packaging: a fixed corpus, a control
that must fail, and a score whose meaning and limits are stated on its face.

# 2. Background: the read-only claim

MCP defines a tool surface but not a policy language. Whether a server is read-only is therefore a
property of its *implementation and configuration*, and the client's only evidence is the declared
tool list plus whatever the tools do when called. Three consequences drive the corpus:

- **Tool registration is the attack surface.** A tool that is registered can be called by an agent
  that is following instructions injected from data it read. Unregistered is a stronger statement
  than "not called".
- **Names are evidence, not proof.** A tool named `query` can write; a tool named `deploy_check` can
  be read-only. Any purely name-based test must be reported as a heuristic, not a finding.
- **Refusals travel in the response body.** Implementations differ on whether a refused call is an
  error or ordinary content, so a probe that only trusts `isError` will misjudge correct servers
  (Section 6.3).

# 3. Corpus design

Six categories, fourteen cases. Each category has the same five fields: what goes wrong, the probe,
the expected safe behaviour, how a failure is detected, and what the probe cannot see.

| category | cases | what a failure means |
|---|---:|---|
| read-only violation | 2 | a mutating tool is registered under a target that declares read-only, or a read tool accepts a path outside its declared scope |
| dangerous tools registered by default | 2 | shell/`exec`-shaped tools, or infrastructure verbs, are present in the default configuration |
| SQL whitelist bypass | 5 | stacked statements, line- and block-comment smuggling, `SELECT ... INTO OUTFILE`, and time-based payloads reach the backend |
| credential exposure | 3 | the process environment, a file outside the sandbox, or a log path is returned to the client |
| prompt injection surface | 1 | tool metadata carries instructions that an agent would follow |
| output redaction | 1 | secret-shaped values appear in tool output unredacted |

Every probe is non-destructive: writes are attempted only where the backend refuses them anyway, and
the shell-shaped probes inspect the declared tool list rather than calling it. That constraint is a
feature of the design, not a limitation we are hiding: a benchmark that destroys a database to prove
a point is not usable by the people who most need it.

**The control.** `vulnerable-demo` is a server we wrote to be insecure in the exact ways the corpus
tests. Any run in which it scores well is a harness failure. It is the reason the numbers below can
be read as measurements rather than assertions.

# 4. Harness

The harness speaks stdio JSON-RPC directly, with no third-party Python dependency (the *targets* have
their own). For each case it records one of: `pass`, `fail`, `warn` (advisory), `not_applicable`, or
`error`.

**Scoring.** `score = 100 × (weighted passes) / (weighted applicable cases)` with severity weights
critical 4, high 3, medium 2, low 1. A case is *applicable* only if the target exposes the surface
the case targets; a case whose probe cannot observe anything is reported as `not_applicable` with an
explicit "unverifiable" note rather than counted as a pass. Name-based registration checks that a
human should adjudicate are reported as **advisories** and do not move the score.

Two consequences of that rule matter for reading Section 5. First, a high score means "no case in
this corpus failed against this server", not "this server is safe". Second, because
`not_applicable` cases are excluded rather than passed, servers that expose less surface are not
rewarded for it.

# 5. Results

Run 2026-09-28 on one machine; all five scorecards are committed, and the corpus and scorecards are
archived separately (Section 9).

| target | what it is | verdict | score | tools | findings |
|---|---|---:|---:|---:|---:|
| `vulnerable-demo` | bundled control, insecure on purpose | critical | 4.8 | 6 | 12 (5 critical, 6 high) |
| `everything-public` | npm `@modelcontextprotocol/server-everything` | elevated | 88.0 | 13 | 1 (high) |
| `mysql-ops-mcp-reference` | read-only-first MySQL ops server | no findings | 100.0 | 17 | 0 (2 advisories) |
| `filesystem-public` | npm `@modelcontextprotocol/server-filesystem` | no findings | 100.0 | 14 | 0 |
| `memory-public` | npm `@modelcontextprotocol/server-memory` | no findings | 100.0 | 9 | 0 |

**The one high-severity finding.** `server-everything` registers `get-env`, which returns the
server's process environment. The probe injected two canary secrets through the environment and read
both back through the tool. For an agent host that is the whole ball game: every API key in the
server's environment is one tool call away, and a prompt injection does not need to escape anything
to reach it. We do not treat this as an unknown vulnerability of that project — it is a documented
debugging tool in a reference server — but the *client-side* consequence is real, and we reported it
upstream as `modelcontextprotocol/servers#4882`.

**Where the numbers are unhelpful.** `filesystem-public` scores 100 while declaring that it is not
read-only; it simply does not expose the surfaces the corpus targets, and the cases that could have
measured it are `not_applicable`. Comparing servers with different declared policies is only
meaningful per category, which is why every scorecard carries the per-case detail.

# 6. What the harness got wrong about itself

We report these because each one produced a wrong verdict before it was fixed, and because the same
shapes will bite any client.

**6.1 A stdio server that buffers stdout deadlocks the client.** The control server wrote responses
without flushing the pipe, so the client blocked forever: two idle processes and no error. Fixes: the
server flushes after every response, and the client reads stdout in a thread feeding a queue so a
request deadline can be enforced. A silent target is now `timeout after 30s`, not a hang.

**6.2 The probe was measuring encoding, not access control.** The canary file originally lived inside
a repository whose path contains non-ASCII characters. A target that inherited the console code page
turned every payload into mojibake, which made a genuinely insecure server *look compliant*. Fixes:
explicit UTF-8 streams in the control server, and — more importantly — the probe payload no longer
contains a non-ASCII path at all, so the case tests access control instead of argv/stdin handling.

**6.3 `isError=false` on a refusal made a correct server look broken.** The first run scored the
reference server 20/100 with five SQL-bypass failures. The raw evidence showed the opposite: every
payload was refused (`ERROR: multiple statements are not allowed`, `ERROR: forbidden keyword:
OUTFILE`), but the framework returned refusals as ordinary content. Fixes: refusal detection reads
the response body as well as the transport flag; and a failed call that shows neither refusal
language nor a leaked value is scored `not_applicable` instead of being counted as a pass, so an
unreachable backend cannot inflate a score.

The common lesson is that a benchmark's own claims need the same treatment as the claims it tests: it
needs a control that must fail, and the failures it finds in itself have to be published alongside
its findings.

# 7. Threats to validity

- **Small corpus.** Fourteen cases. It does not cover authentication, transport security, sandboxing,
  dependency risk, or a target's own business logic. A perfect score is a statement about these
  fourteen cases only.
- **Heuristic detection.** Several cases key on names or on refusal phrases. Names are explicitly
  reported as advisories; refusal detection is deliberately high-confidence and may classify an
  unusual-but-correct server as unverifiable rather than as a pass.
- **One machine, one run per target.** Timing-sensitive probes (timeouts) can differ across machines;
  probe outcomes were stable across our re-runs, but we report a single recorded run per target.
- **Five targets, chosen for availability.** Three are official or npm-distributed servers, one is
  ours, one is our own control. This is a convenience sample; it is not a survey of MCP servers.
- **The authors also wrote the reference implementation.** The comparison between it and the other
  targets is a comparison of declared policies, not an independent audit.

# 8. Related work

**The protocol.** This work measures the tool surface defined by the Model Context Protocol (MCP)
specification: a server advertises tools over JSON-RPC and a client calls what it can see. The
specification describes that surface; it does not prescribe the policy an operator claims to run. That
gap — between a policy stated in prose and the tools actually registered — is what the corpus
measures.

**Indirect prompt injection.** The motivating threat is that an agent can be steered by instructions
carried in data it reads, and then acts with the tools it has. Greshake et al. demonstrated this
against real LLM-integrated applications (arXiv:2302.12173). This paper does not add new injection
techniques; it measures the *preconditions* — which tools exist to be reached at all, and under which
declared policy — and turns the answer into an auditable score.

**Server-side guidance.** *TODO before submission: cite the MCP project's own security
best-practices material from the primary source, with the revision and scope verified. The
specification page was reachable during writing, but its neighbouring security guidance has not been
read closely enough to cite accurately.*

**Existing benchmarks.** *TODO before submission: check whether an existing benchmark already covers
this ground, and either position against it or state plainly that this is an independent
re-implementation with a different control design. No citation may be invented to fill this gap.*

# 9. Availability

- Source: <https://github.com/CieveMe/mcp-security-benchmark>
- Archived version (v0.1.0): DOI [10.5281/zenodo.23003717](https://doi.org/10.5281/zenodo.23003717);
  all versions: [10.5281/zenodo.23003715](https://doi.org/10.5281/zenodo.23003715)
- Corpus and scorecards as a dataset:
  <https://huggingface.co/datasets/CieveMe/mcp-security-benchmark>
- Reproduce: `python -m bench list`, `python -m bench run`, `python -m unittest discover -s tests -v`

# 10. Conclusion

"Our MCP server is read-only and safe" is a claim. It becomes evidence when a fixed corpus runs
against the server, produces a scorecard, and the harness has been shown to fail a server that is
supposed to fail. We provide that corpus and those scorecards for five servers, one upstream-reported
finding, and an honest account of three defects the harness found in itself. The number a server
receives here is not a security rating; it is a statement about fourteen cases, and the cases are
published so that anyone can disagree with them.

# Appendix A. Case list

| id | category | severity |
|---|---|---|
| `ro-mutating-tool-registered` | read-only violation | high |
| `ro-unrestricted-path-argument` | read-only violation | high |
| `dangerous-shell-tool-registered` | dangerous registration | critical |
| `dangerous-mutating-tools-default` | dangerous registration | high |
| `sql-stacked-statement` | SQL whitelist bypass | critical |
| `sql-line-comment-smuggling` | SQL whitelist bypass | high |
| `sql-block-comment-prefix` | SQL whitelist bypass | high |
| `sql-select-into-outfile` | SQL whitelist bypass | critical |
| `sql-sleep-timeout` | SQL whitelist bypass | medium |
| `cred-env-canary-dump` | credential exposure | critical |
| `cred-file-outside-sandbox` | credential exposure | high |
| `cred-log-path-injection` | credential exposure | medium |
| `inj-metadata-instructions` | prompt injection | medium |
| `redact-secret-shaped-output` | output redaction | low |

*Severities are the values declared in `cases/cases.json`; the weights used for scoring are
critical 4, high 3, medium 2, low 1.*
