# MCP security scorecard - `mysql-ops-mcp-reference`

- generated: n/a
- protocol version: 2025-06-18
- server info: `{'name': 'mysql-ops-mcp', 'version': '1.27.0'}`
- tools exposed: 17
- verdict: **no_findings**  |  risk score: **100.0** (100 = no findings)  |  findings: 0 (critical 0, high 0)  |  advisories: 2

> Reference implementation under study: read-only-first MCP server (SQL whitelist, mutating tools off by default, secret redaction). No database is reachable from this machine, so tool calls that need the backend are expected to fail; registration and validator behaviour are still observable.

## Categories

| category | verdict | score | pass | fail | warn | n/a | error |
|---|---|---:|---:|---:|---:|---:|---:|
| read-only-violation | not_tested | n/a | 0 | 0 | 1 | 1 | 0 |
| dangerous-registration | pass | 100.0 | 1 | 0 | 1 | 0 | 0 |
| sql-whitelist-bypass | pass | 100.0 | 5 | 0 | 0 | 0 | 0 |
| credential-exposure | pass | 100.0 | 1 | 0 | 0 | 2 | 0 |
| prompt-injection | pass | 100.0 | 1 | 0 | 0 | 0 | 0 |
| output-redaction | pass | 100.0 | 1 | 0 | 0 | 0 | 0 |

## Advisories (not scored)

These are name-level or environment-level suspicions that the harness cannot settle on its own. They are listed so a human can confirm or dismiss them, and they deliberately do not move the score.

| case | tool | detail |
|---|---|---|
| `ro-mutating-tool-registered` | `deploy_check` | 1 tool name(s) mention a mutating verb but carry a read-only suffix; needs human confirmation |
| `dangerous-mutating-tools-default` | `deploy_check` | 1 tool name(s) mention a mutating verb but carry a read-only suffix; needs human confirmation |

## Findings

None. Every applicable probe either passed or did not apply to this target.

## Probe detail

| case | category | severity | status | tool | detail |
|---|---|---|---|---|---|
| `ro-mutating-tool-registered` | read-only-violation | critical | warn | `deploy_check` | 1 tool name(s) mention a mutating verb but carry a read-only suffix; needs human confirmation |
| `ro-unrestricted-path-argument` | read-only-violation | high | not_applicable | `None` | no tool matches /^(read|load|fetch|cat|open)/ |
| `dangerous-shell-tool-registered` | dangerous-registration | critical | pass | `None` | tool is not registered |
| `dangerous-mutating-tools-default` | dangerous-registration | high | warn | `deploy_check` | 1 tool name(s) mention a mutating verb but carry a read-only suffix; needs human confirmation |
| `sql-stacked-statement` | sql-whitelist-bypass | critical | pass | `custom_query` | server refused in the response body (isError was not set) |
| `sql-line-comment-smuggling` | sql-whitelist-bypass | critical | pass | `custom_query` | server refused in the response body (isError was not set) |
| `sql-block-comment-prefix` | sql-whitelist-bypass | high | pass | `custom_query` | server refused in the response body (isError was not set) |
| `sql-select-into-outfile` | sql-whitelist-bypass | critical | pass | `custom_query` | server refused in the response body (isError was not set) |
| `sql-sleep-timeout` | sql-whitelist-bypass | medium | pass | `custom_query` | server refused in the response body (isError was not set) |
| `cred-env-canary-dump` | credential-exposure | high | not_applicable | `None` | no tool matches /(env|environ|printenv|get_env|config|settings|info)/ |
| `cred-file-outside-sandbox` | credential-exposure | high | not_applicable | `None` | no tool matches /(read_file|read_text_file|read|cat|get_file|file_info)/ |
| `cred-log-path-injection` | credential-exposure | medium | pass | `server_logs` | response contained none of the forbidden patterns |
| `inj-metadata-instructions` | prompt-injection | high | pass | `None` | scanned 17 tool description(s), none contains imperative instructions |
| `redact-secret-shaped-output` | output-redaction | medium | pass | `activity_stats` | server refused the request, so nothing could leak |
