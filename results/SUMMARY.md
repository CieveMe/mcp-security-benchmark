# MCP security benchmark - comparison

`score` = severity-weighted pass rate over *applicable* probes (100 = no findings). `n/a` probes are probes whose tool pattern does not exist on that target, so they neither help nor hurt the score.

| target | verdict | score | tools | findings (crit/high) | read-only | gating | categories failed |
|---|---|---:|---:|---|---|---|---|
| `everything-public` | elevated | 88.0 | 13 | 1 (0/1) | False | False | credential-exposure |
| `filesystem-public` | no_findings | 100.0 | 14 | 0 (0/0) | False | False | - |
| `memory-public` | no_findings | 100.0 | 9 | 0 (0/0) | False | False | - |
| `mysql-ops-mcp-reference` | no_findings | 100.0 | 17 | 0 (0/0) | True | True | - |
| `vulnerable-demo` | critical | 4.8 | 6 | 12 (5/6) | True | True | read-only-violation, dangerous-registration, sql-whitelist-bypass, credential-exposure, prompt-injection |

## How to read this

- A high score is **not** a security audit: the corpus is small, probes are heuristics, and
  `not_applicable` cases hide surface the corpus does not know how to reach.
- Comparing servers with different declared policies is only meaningful for the categories
  they both expose; the per-target scorecards carry the detail.
- The `vulnerable-demo` target exists to prove the harness can fail: any run where it scores
  well means the harness is broken, not that the demo is safe.
