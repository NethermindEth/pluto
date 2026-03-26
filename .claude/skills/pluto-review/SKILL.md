---
name: pluto-review
description: Pluto-specific code review guidelines. Use as a general guideline when asked to conduct a code review.
---

Principles:

- Functional equivalence first; document and justify deviations.
- Evidence-based: prefer tests, outputs, and file/line references over guesses.
- Minimal change bias; avoid scope creep.
- No time estimates in review output.

When producing a review, include:

1. Summary (1–3 sentences)
2. Findings (ordered by severity)
3. Parity matrix (if applicable)
4. Tests (run or not run)
5. Open questions/assumptions

Severity model:

- Critical: breaks contract, security issue, incompatible output/protocol.
- High: user-visible regression or parity gap with operational impact.
- Medium: behavioral difference with limited impact or edge cases.
- Low: minor inconsistency or optional improvement.

Findings format (use `path:line` references, 1-based):

```text
- [Severity] Title
  Impact: ...
  Evidence: pluto/crates/foo/src/lib.rs:123
  Go reference: charon/cmd/foo.go:456
  Recommendation: ...
```

Parity matrix template:

| Component | Go | Rust | Match | Notes |
| --- | --- | --- | --- | --- |
| CLI flag --foo | present | present | yes | |
| Error string for missing key | "..." | "..." | no | mismatch in punctuation |
| Wire format | pbio | pbio | yes | |
