# Upstream issue draft — `get-env` on the Everything reference server

**Status: draft, not posted.** Posting it under the repository owner's GitHub identity is an owner
action (see the publish checklist below). Read the framing note first.

## Framing note (please read before posting)

`get-env` is *documented* on this server as a debugging helper ("Returns all environment variables,
helpful for debugging MCP server configuration"). It is a reference/test server, so an
environment dump is plausibly intentional. Reporting it as a vulnerability would be noise and would
make the report easy to dismiss.

What is worth reporting is the consequence for anyone who copies the reference server into a real
deployment or connects it to an autonomous agent, and the difference between the description
("helpful for debugging configuration") and the behaviour (returns *every* inherited variable,
including credentials). The draft below is therefore a **documentation/guard** request, not a
vulnerability claim. If the maintainers say the tool is intentionally unrestricted for testing, the
reasonable outcome is a warning in the description plus a doc line — and that outcome is a win,
because the finding is then recorded upstream instead of only in this repository.

## Suggested title

`get-env` returns every inherited variable (including credentials) — consider a warning or an opt-in guard

## Suggested body

Hi — I maintain a small probe harness that runs a fixed corpus of security-relevant probes against MCP
servers over stdio (read-only contract violations, dangerous tools registered by default, SQL
whitelist bypasses, credential exposure, prompt-injection surface in tool metadata, unredacted
output). I ran it against five servers, and the Everything reference server produced the only
high-severity finding of the run, which is why I am writing rather than silently publishing it.

### What happens

The harness injects two canary values into the server process environment and then calls every tool
whose name suggests an environment or configuration dump. `get-env` returns them:

```
"MCPBENCH_CANARY_SECRET": "mcpbench-canary-3f9a1c2d7e5b",
"MCPBENCH_CANARY_TOKEN": "sk-mcpbench-canary-0000deadbeef1111",
```

(Those are the harness's own fake values; they exist so a leak can be proven by content instead of
inference. I redacted everything else the call returned.)

### How to reproduce

```bash
npx -y @modelcontextprotocol/server-everything    # stdio; serverInfo: mcp-servers/everything 2.0.0
```

Then, over stdio, in order: `initialize` (protocolVersion `2025-06-18`), the
`notifications/initialized` notification, and

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get-env","arguments":{}}}
```

Set `MCPBENCH_CANARY_SECRET` to any value first and observe it in the response. The harness automates
exactly this; the raw transcript and the scorecard are committed in my repository.

### Why I think it is worth a change

1. The tool description says it is "helpful for debugging MCP server configuration". It does not say
   that the response contains every inherited variable. A reader — or an agent that decides which
   tools to call — has no way to know the difference between "some configuration" and "the whole
   environment".
2. Reference servers get copied. The environment of a deployed MCP server commonly holds API keys,
   database URLs and cloud credentials for the very systems the server is allowed to touch, which
   turns one tool call into full credential disclosure — including into whatever transcript the
   client stores.
3. In my corpus this was the highest-severity result across five servers, so the cost of the current
   behaviour is not hypothetical in a comparison table; it is the single thing that stands out.

### Possible directions (any of these would resolve my report)

- Add an explicit warning to the tool description, e.g. "Debugging only — returns every environment
  variable, including credentials. Do not enable in production or with a real agent." (cheapest, and
  consistent with the server's purpose).
- Gate it behind an environment flag or a CLI switch alongside the other demo toggles, so the default
  surface of the reference server cannot disclose credentials.
- Redact values whose names match secret patterns (`*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASSWORD*`)
  before returning them — keeps the debugging value, drops the disclosure.

Happy to test a patch, or to re-run the corpus against a build that changes this. If the current
behaviour is intentional for reference-server testing, a one-line note in the description would be
enough for me to close this on my side; I mainly want it recorded rather than only in a comparison
table.

## After posting

- Link the finding to the benchmark result (`docs/threat-model.md`, category 4) and to the scorecard
  in this repository.
- Re-run `python -m bench run --target everything-public` once a new version is published, and record
  the result in the repository rather than in a chat log.
