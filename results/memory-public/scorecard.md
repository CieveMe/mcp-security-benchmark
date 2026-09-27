# MCP security scorecard - `memory-public`

- generated: n/a
- protocol version: 2025-06-18
- server info: `{'name': 'memory-server', 'version': '0.6.3'}`
- tools exposed: 9
- verdict: **no_findings**  |  risk score: **100.0** (100 = no findings)  |  findings: 0 (critical 0, high 0)  |  advisories: 0

> Public knowledge-graph server (npm @modelcontextprotocol/server-memory). Registers create/delete tools by design; the interesting part is what it exposes to an agent and where its state file lives.

## Categories

| category | verdict | score | pass | fail | warn | n/a | error |
|---|---|---:|---:|---:|---:|---:|---:|
| read-only-violation | not_tested | n/a | 0 | 0 | 0 | 2 | 0 |
| dangerous-registration | not_tested | n/a | 0 | 0 | 0 | 2 | 0 |
| sql-whitelist-bypass | not_tested | n/a | 0 | 0 | 0 | 5 | 0 |
| credential-exposure | pass | 100.0 | 1 | 0 | 0 | 2 | 0 |
| prompt-injection | pass | 100.0 | 1 | 0 | 0 | 0 | 0 |
| output-redaction | not_tested | n/a | 0 | 0 | 0 | 1 | 0 |

## Findings

None. Every applicable probe either passed or did not apply to this target.

## Probe detail

| case | category | severity | status | tool | detail |
|---|---|---|---|---|---|
| `ro-mutating-tool-registered` | read-only-violation | critical | not_applicable | `None` | target does not declare the `read_only` gate |
| `ro-unrestricted-path-argument` | read-only-violation | high | not_applicable | `None` | target does not declare a read-only contract |
| `dangerous-shell-tool-registered` | dangerous-registration | critical | not_applicable | `None` | target does not declare dangerous-tool gating |
| `dangerous-mutating-tools-default` | dangerous-registration | high | not_applicable | `None` | target does not declare the `no_dangerous_tools` gate |
| `sql-stacked-statement` | sql-whitelist-bypass | critical | not_applicable | `None` | no tool matches /(sql|query|execute|db)/ |
| `sql-line-comment-smuggling` | sql-whitelist-bypass | critical | not_applicable | `None` | no tool matches /(sql|query|execute|db)/ |
| `sql-block-comment-prefix` | sql-whitelist-bypass | high | not_applicable | `None` | no tool matches /(sql|query|execute|db)/ |
| `sql-select-into-outfile` | sql-whitelist-bypass | critical | not_applicable | `None` | no tool matches /(sql|query|execute|db)/ |
| `sql-sleep-timeout` | sql-whitelist-bypass | medium | not_applicable | `None` | no tool matches /(sql|query|execute|db)/ |
| `cred-env-canary-dump` | credential-exposure | high | not_applicable | `None` | no tool matches /(env|environ|printenv|get_env|config|settings|info)/ |
| `cred-file-outside-sandbox` | credential-exposure | high | pass | `read_graph` | response contained none of the forbidden patterns |
| `cred-log-path-injection` | credential-exposure | medium | not_applicable | `None` | no tool matches /log/ |
| `inj-metadata-instructions` | prompt-injection | high | pass | `None` | scanned 9 tool description(s), none contains imperative instructions |
| `redact-secret-shaped-output` | output-redaction | medium | not_applicable | `None` | no tool matches /(inspect|logs|status|config|query|docker|stats|info)/ |
