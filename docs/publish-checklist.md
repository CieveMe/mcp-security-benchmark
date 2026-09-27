# Publish checklist (owner actions)

The repository is ready to publish; the steps that need GitHub credentials are not automated here.

## 1. Before creating the remote

```bash
python -m unittest discover -s tests -v     # 10 tests
python -m bench run                          # 5 targets, writes results/
git status --short                           # must be clean
```

Optional: point the reference target at a checkout of that project first
(`MCPBENCH_MYSQL_OPS_DIR`); the other four targets need only Python and Node.

## 2. Create the public repository and push

```bash
git remote add github https://github.com/<account>/mcp-security-benchmark.git
git push -u github main
```

Suggested repository description:

> Fixed-case security probes for MCP servers over stdio: read-only contract, dangerous tools,
> SQL whitelist bypass, credential exposure, prompt-injection surface, unredacted output. Five
> targets, reproducible scorecards, redacted evidence.

Suggested topics: `mcp`, `model-context-protocol`, `security`, `benchmark`, `ai-agents`, `python`.

## 3. After publishing

- Add the finding link to `docs/threat-model.md` (category 4) once the upstream issue exists, and keep
  `docs/upstream-issue-server-everything.md` as the record of what was reported and when.
- Re-run the corpus when a target publishes a new version and commit the refreshed scorecard; the
  scorecards are deterministic, so a diff means something really changed (or a target changed
  behaviour).
- Do **not** paste raw target output into issues, screenshots or chat: the redaction rules in
  `bench/probes.py` exist because a credential-exposure finding is exactly the kind of result that
  republishes the secret it is reporting.

## 4. Optional next steps (v0.2 candidates)

1. SQL whitelist variants: case folding, Unicode homoglyphs, `/*!...*/` version comments,
   `WITH ... DELETE`, plus a database-side assertion (read a row count to confirm nothing changed) so
   "rejected" is verified by fact, not by response text.
2. Authentication and multi-tenant categories (needs two identities with different scopes).
3. Container-per-target execution (this machine's Docker daemon was not running, so only the
   npx/python launch paths are exercised today).
4. Policy file support: let a target declare "read-only", "no shell", "no environment access" and
   score against that declaration directly, instead of the heuristic gates used now.
