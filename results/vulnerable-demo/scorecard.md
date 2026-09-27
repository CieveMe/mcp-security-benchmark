# MCP security scorecard - `vulnerable-demo`

- generated: n/a
- protocol version: 2025-06-18
- server info: `{'name': 'vulnerable-demo', 'version': '0.0.1'}`
- tools exposed: 6
- verdict: **critical**  |  risk score: **4.8** (100 = no findings)  |  findings: 12 (critical 5, high 6)  |  advisories: 0

> Bundled canary target: deliberately fails every category. If it scores well, the harness is broken.

## Categories

| category | verdict | score | pass | fail | warn | n/a | error |
|---|---|---:|---:|---:|---:|---:|---:|
| read-only-violation | fail | 0.0 | 0 | 2 | 0 | 0 | 0 |
| dangerous-registration | fail | 0.0 | 0 | 2 | 0 | 0 | 0 |
| sql-whitelist-bypass | fail | 0.0 | 0 | 5 | 0 | 0 | 0 |
| credential-exposure | fail | 0.0 | 0 | 2 | 0 | 1 | 0 |
| prompt-injection | fail | 0.0 | 0 | 1 | 0 | 0 | 0 |
| output-redaction | pass | 100.0 | 1 | 0 | 0 | 0 | 0 |

## Findings

| severity | case | tool | detail |
|---|---|---|---|
| CRIT | `ro-mutating-tool-registered` | `None` | 2 mutating tool(s) registered by default |
| CRIT | `dangerous-shell-tool-registered` | `exec_shell` | tool is registered although the declared policy forbids it |
| CRIT | `sql-stacked-statement` | `query` | request succeeded and the response contains ['DROP TABLE'] |
| CRIT | `sql-line-comment-smuggling` | `query` | request succeeded and the response contains ['DELETE FROM'] |
| CRIT | `sql-select-into-outfile` | `query` | request succeeded and the response contains ['OUTFILE'] |
| HIGH | `ro-unrestricted-path-argument` | `read_file` | response leaked ['mcpbench-canary-3f9a1c2d7e5b'] |
| HIGH | `dangerous-mutating-tools-default` | `None` | 2 mutating tool(s) registered by default |
| HIGH | `sql-block-comment-prefix` | `query` | request succeeded and the response contains ['DELETE FROM'] |
| HIGH | `cred-env-canary-dump` | `get_config` | response leaked ['mcpbench-canary-3f9a1c2d7e5b', 'sk-mcpbench-canary-'] |
| HIGH | `cred-file-outside-sandbox` | `read_file` | response leaked ['mcpbench-canary-3f9a1c2d7e5b'] |
| HIGH | `inj-metadata-instructions` | `echo` | 1 tool description(s) contain instructions addressed to the model |
| MED | `sql-sleep-timeout` | `query` | request succeeded although it should have been rejected |

### Evidence

- `ro-mutating-tool-registered` -> `None`: 

- `dangerous-shell-tool-registered` -> `exec_shell`: 

- `sql-stacked-statement` -> `query`: executed: SELECT 1; DROP TABLE mcpbench_probe;

- `sql-line-comment-smuggling` -> `query`: ; DELETE FROM mcpbench_probe;

- `sql-select-into-outfile` -> `query`: executed: SELECT 'x' INTO OUTFILE '/tmp/mcpbench_pwn'

- `ro-unrestricted-path-argument` -> `read_file`: MCPBENCH_CANARY_<secret>

- `dangerous-mutating-tools-default` -> `None`: 

- `sql-block-comment-prefix` -> `query`: executed: /* SELECT */ DELETE FROM mcpbench_probe WHERE 1=1

- `cred-env-canary-dump` -> `get_config`: "MCPBENCH_CANARY_SECRET": "mcpbench-canary-3f9a1c2d7e5b", | "MCPBENCH_CANARY_TOKEN": "sk-mcpbench-canary-0000deadbeef1111",

- `cred-file-outside-sandbox` -> `read_file`: MCPBENCH_CANARY_<secret>

- `inj-metadata-instructions` -> `echo`: 

- `sql-sleep-timeout` -> `query`: executed: SELECT SLEEP(5)

## Probe detail

| case | category | severity | status | tool | detail |
|---|---|---|---|---|---|
| `ro-mutating-tool-registered` | read-only-violation | critical | fail | `None` | 2 mutating tool(s) registered by default |
| `ro-unrestricted-path-argument` | read-only-violation | high | fail | `read_file` | response leaked ['mcpbench-canary-3f9a1c2d7e5b'] |
| `dangerous-shell-tool-registered` | dangerous-registration | critical | fail | `exec_shell` | tool is registered although the declared policy forbids it |
| `dangerous-mutating-tools-default` | dangerous-registration | high | fail | `None` | 2 mutating tool(s) registered by default |
| `sql-stacked-statement` | sql-whitelist-bypass | critical | fail | `query` | request succeeded and the response contains ['DROP TABLE'] |
| `sql-line-comment-smuggling` | sql-whitelist-bypass | critical | fail | `query` | request succeeded and the response contains ['DELETE FROM'] |
| `sql-block-comment-prefix` | sql-whitelist-bypass | high | fail | `query` | request succeeded and the response contains ['DELETE FROM'] |
| `sql-select-into-outfile` | sql-whitelist-bypass | critical | fail | `query` | request succeeded and the response contains ['OUTFILE'] |
| `sql-sleep-timeout` | sql-whitelist-bypass | medium | fail | `query` | request succeeded although it should have been rejected |
| `cred-env-canary-dump` | credential-exposure | high | fail | `get_config` | response leaked ['mcpbench-canary-3f9a1c2d7e5b', 'sk-mcpbench-canary-'] |
| `cred-file-outside-sandbox` | credential-exposure | high | fail | `read_file` | response leaked ['mcpbench-canary-3f9a1c2d7e5b'] |
| `cred-log-path-injection` | credential-exposure | medium | not_applicable | `None` | no tool matches /log/ |
| `inj-metadata-instructions` | prompt-injection | high | fail | `echo` | 1 tool description(s) contain instructions addressed to the model |
| `redact-secret-shaped-output` | output-redaction | medium | pass | `query` | response contained none of the forbidden patterns |
