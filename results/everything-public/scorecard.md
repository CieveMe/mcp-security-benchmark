# MCP security scorecard - `everything-public`

- generated: n/a
- protocol version: 2025-06-18
- server info: `{'name': 'mcp-servers/everything', 'title': 'Everything Reference Server', 'version': '2.0.0'}`
- tools exposed: 13
- verdict: **elevated**  |  risk score: **88.0** (100 = no findings)  |  findings: 1 (critical 0, high 1)  |  advisories: 0

> Public demo server (npm @modelcontextprotocol/server-everything). Exposes environment and echo-style tools, so the canary probes are directly applicable.

## Categories

| category | verdict | score | pass | fail | warn | n/a | error |
|---|---|---:|---:|---:|---:|---:|---:|
| read-only-violation | not_tested | n/a | 0 | 0 | 0 | 2 | 0 |
| dangerous-registration | not_tested | n/a | 0 | 0 | 0 | 2 | 0 |
| sql-whitelist-bypass | pass | 100.0 | 5 | 0 | 0 | 0 | 0 |
| credential-exposure | fail | 40.0 | 1 | 1 | 0 | 1 | 0 |
| prompt-injection | pass | 100.0 | 1 | 0 | 0 | 0 | 0 |
| output-redaction | not_tested | n/a | 0 | 0 | 0 | 1 | 0 |

## Findings

| severity | case | tool | detail |
|---|---|---|---|
| HIGH | `cred-env-canary-dump` | `get-env` | response leaked ['mcpbench-canary-3f9a1c2d7e5b', 'sk-mcpbench-canary-'] |

### Evidence

- `cred-env-canary-dump` -> `get-env`: "MCPBENCH_CANARY_SECRET": "mcpbench-canary-3f9a1c2d7e5b", | "MCPBENCH_CANARY_TOKEN": "sk-mcpbench-canary-0000deadbeef1111",

## Probe detail

| case | category | severity | status | tool | detail |
|---|---|---|---|---|---|
| `ro-mutating-tool-registered` | read-only-violation | critical | not_applicable | `None` | target does not declare the `read_only` gate |
| `ro-unrestricted-path-argument` | read-only-violation | high | not_applicable | `None` | target does not declare a read-only contract |
| `dangerous-shell-tool-registered` | dangerous-registration | critical | not_applicable | `None` | target does not declare dangerous-tool gating |
| `dangerous-mutating-tools-default` | dangerous-registration | high | not_applicable | `None` | target does not declare the `no_dangerous_tools` gate |
| `sql-stacked-statement` | sql-whitelist-bypass | critical | pass | `simulate-research-query` | server rejected the request |
| `sql-line-comment-smuggling` | sql-whitelist-bypass | critical | pass | `simulate-research-query` | server rejected the request |
| `sql-block-comment-prefix` | sql-whitelist-bypass | high | pass | `simulate-research-query` | server rejected the request |
| `sql-select-into-outfile` | sql-whitelist-bypass | critical | pass | `simulate-research-query` | server rejected the request |
| `sql-sleep-timeout` | sql-whitelist-bypass | medium | pass | `simulate-research-query` | server rejected the request |
| `cred-env-canary-dump` | credential-exposure | high | fail | `get-env` | response leaked ['mcpbench-canary-3f9a1c2d7e5b', 'sk-mcpbench-canary-'] |
| `cred-file-outside-sandbox` | credential-exposure | high | not_applicable | `None` | no tool matches /(read_file|read_text_file|read|cat|get_file|file_info)/ |
| `cred-log-path-injection` | credential-exposure | medium | pass | `toggle-simulated-logging` | response contained none of the forbidden patterns |
| `inj-metadata-instructions` | prompt-injection | high | pass | `None` | scanned 13 tool description(s), none contains imperative instructions |
| `redact-secret-shaped-output` | output-redaction | medium | not_applicable | `simulate-research-query` | call failed for an unrelated reason; this probe observed nothing (unverifiable) |
