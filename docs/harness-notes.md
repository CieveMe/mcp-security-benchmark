# Harness notes: three bugs the benchmark found in *itself*

Recorded because each one would have produced a wrong verdict, and because they are the same
failure shapes any MCP client hits.

## 1. A stdio server that buffers stdout deadlocks the client

The bundled canary server wrote responses through an `io.TextIOWrapper(..., write_through=True)` and
assumed that was enough. It was not: `write_through` hands the text to the *binary* buffer, and a
pipe buffers. The server answered nothing until it exited, so the client waited forever — the run
hung with two idle processes and no error.

Two fixes, both kept:

- the server flushes explicitly after every response;
- the client now reads stdout in a **thread feeding a queue**, so a request deadline is enforced
  instead of a blocking `readline()` ignoring it. A silent target is now a
  `timeout after 30s waiting for a response` error, not a hang.

This is a general MCP rule: any server that forgets `flush()` on a pipe is unusable, and any client
without a read timeout will appear to hang rather than report the misbehaving server.

## 2. Encoding: the Chinese path in this workspace corrupted probe payloads

The canary file first lived inside the repository. Because the repository path contains non-ASCII
characters, the probe payload only reached the target correctly if the target decoded stdin as UTF-8.
The bundled Python server inherited the console code page instead and turned every path into
mojibake (`No such file or directory`), which made a genuinely insecure server look compliant on the
file probes.

- the server now uses explicit UTF-8 streams, as well-behaved servers do;
- **probe payloads no longer contain non-ASCII paths at all**: the canary lives in an ASCII temp
  directory, so the benchmark tests access control instead of argv/stdin encoding.

## 3. `isError=false` on a refusal made a correct server look broken

The first run scored the reference `mysql-ops-mcp` at 20/100 with five "SQL bypass" failures. The raw
evidence showed the opposite: every payload was refused (`ERROR: multiple statements are not
allowed`, `ERROR: forbidden keyword: OUTFILE`), but FastMCP returned those refusals as ordinary
content with `isError=false`, and the classifier treated "not an error" as "succeeded".

Fixes:

- refusal detection reads the response **body** as well as `isError`, using high-confidence markers
  (`ERROR:`, "not allowed", "forbidden", "read-only", "refused", …);
- a failed call that shows no refusal language and no leaked value is scored
  `not_applicable` — "unverifiable" — instead of a free pass, so an unreachable backend cannot
  inflate a score.

Two lessons worth keeping: a probe that only trusts transport-level flags will misjudge real
servers, and **every finding must be read back from the raw response** before it is reported. The
raw excerpt is kept in each scorecard for exactly that reason.

## 4. Heuristics need a tier that does not score

Name-based checks produced two false positives on the reference implementation (`deploy_check`
matches a mutating-verb pattern but is a read-only diagnostic). Rather than tune an allowlist until
the result looked good, the harness gained a third outcome: `warn`. Advisories are reported with the
tool name and never move the score, and the README says so.
