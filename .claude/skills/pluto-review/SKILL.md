---
name: pluto-review
description: Pluto-specific code review guidelines. Use as a general guideline when asked to conduct a code review.
---

Principles:

- Functional equivalence first; document and justify deviations.
- Use Charon v1.7.1 as the Go parity baseline. For DKG, sync, reshare, FetchDefinition, and peer-indexed broadcast code, also apply the [February 20, 2026 Trail of Bits Charon Pedersen DKG audit](https://github.com/ObolNetwork/charon/blob/main/docs/audit/2026%20-%20Charon%20V2%20Audit%20-%20TrailOfBits.pdf) fixes when v1.7.1 behavior conflicts with the audit.
- Evidence-based: prefer tests, outputs, and file/line references over guesses.
- Minimal change bias; avoid scope creep.
- No time estimates in review output.

Audit-aware DKG review checklist:

- TOB-CHARON-1: Reject complete cluster replacement and reshare paths with fewer than the old threshold of participating old nodes.
- TOB-CHARON-2: Validate DKG thresholds before constructing protocol state: threshold >= 1 and threshold <= node count.
- TOB-CHARON-3: Bound size-prefixed sync/protobuf reads before allocating buffers.
- TOB-CHARON-4: Verify broadcast sender identity matches the claimed peer index.
- TOB-CHARON-5: When converting `oldShareIndices` into `PublicShares`, store each public key under its actual share index (`oi`), not the compact loop position (`i + 1`).
- TOB-CHARON-6: Generate distinct nonces per validator iteration in DKG and reshare DKG; no nonce reuse across iterations.
- TOB-CHARON-7: Treat out-of-range share numbers as structured errors, not panics.
- TOB-CHARON-8: Validate polynomial commitments for new nodes during reshare against expected validator public keys.
- TOB-CHARON-9: Bound `FetchDefinition` HTTP body reads before `ReadAll`-style buffering.

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
