# Experiment plan before the benchmark paper is submitted

The draft in `paper.md` is written from data that already exists. This file lists what should be
added **before** it goes anywhere public as a paper, in priority order, with a cost estimate and the
claim each item would earn or protect.

## 1. More targets (highest value)

Five targets is a convenience sample. The paper says so, and a reviewer will still ask for more.

- Add **8–12 more public MCP servers** (official `modelcontextprotocol/servers` set plus popular
  community servers that install from npm). The constraint is real: this machine has npm access but
  **no PyPI access and no GPU**, so targets that need Python packages or model weights are out of
  scope and should be listed as excluded with the reason.
- Add **one more deliberately insecure control** with a *different* failure profile (for example: a
  read-only-looking server that hides a write behind `custom_query`). One control proves the harness
  can fail; two controls with different shapes prove it does not only detect our own bug.
- Earns: "we tested N servers and found M findings" instead of "we tested five".

## 2. Stability of the measurement

- Run the full corpus **twice per target** and commit both scorecards; report whether any probe
  changed verdict. If one does, that probe is timing-dependent and must say so.
- Earns: the difference between "a scorecard we produced" and "a reproducible scorecard".

## 3. Per-category reporting

- The current table is aggregate. Add a per-category matrix (category × target) to the paper.
- Earns: the honest comparison the README calls for — targets with different declared policies are
  only comparable per category.

## 4. Related work (blocking, cannot be skipped)

- Cite the MCP specification, the prompt-injection literature and any existing agent-security
  benchmarks **from primary sources**, verified one by one. No citation may be written from memory.
- If an existing benchmark already covers this ground, the paper must position against it or state
  plainly that it is a re-implementation with a different control design. A duplicate-topic surprise
  at review time is much worse than saying it up front.

## 5. Venue

| venue | gate | note |
|---|---|---|
| arXiv (`cs.CR` / `cs.SE`) | **needs an endorsement** | fastest, no review, but the endorsement has to be obtained from an existing author |
| OpenReview workshop | none | seasonal deadlines; a short paper is usually enough |
| Zenodo preprint only | none | citable and indexed, but carries no review label |

Convert `paper.md` to LaTeX once the venue is fixed; the content should not change in translation.

## 6. Ethics and disclosure checklist

- Test only servers we are permitted to test: our own, and public servers installed locally as a
  user. No finding may come from exploiting a service we do not control.
- Any finding that affects a third party goes upstream **before** publication (the `get-env` finding
  was reported as `servers#4882`).
- The corpus is non-destructive by construction; keep it that way, and say so in the paper.
- No hostnames, credentials, customer data or local paths in the paper, the corpus or the scorecards.

## 7. Author metadata

- ORCID: `0009-0009-1526-5793`; affiliation: `Independent Researcher` (same value used for the JOSS
  draft and arXiv).
