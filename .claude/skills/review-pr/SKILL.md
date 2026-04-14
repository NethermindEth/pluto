---
name: review-pr
description: >
  Full multi-agent code review for a Pluto PR. Spawns parallel agents covering
  functional correctness, security, Rust style, and code quality, then posts
  all findings as isolated GitHub review comments and submits a final
  approve/request-changes verdict. Invoke as `/review-pr <PR-number>` or
  `/review-pr <GitHub-PR-URL>`.
---

# Review PR

You are orchestrating a thorough code review for a Pluto pull request.

## Input

The argument is either a PR number (e.g. `311`) or a full GitHub PR URL. The
repository is always `NethermindEth/pluto`.

Resolve the PR number if a URL was given:
```bash
# From URL like https://github.com/NethermindEth/pluto/pull/311
PR=311
```

## Step 1 — Gather context

Run these in parallel:
```bash
gh pr view $PR --repo NethermindEth/pluto \
  --json title,body,files,additions,deletions,headRefName,commits
gh pr diff $PR --repo NethermindEth/pluto
```

Read every changed file from disk (the branch may already be checked out).
If a file is not available locally, use the raw diff.

Also note the head commit SHA — you will need it for the review API call.

## Step 2 — Parallel agent review

Spawn **four agents in a single message** so they run concurrently.  Give each
agent the full diff and relevant file contents in its prompt.

| Agent | Skill | Focus |
|---|---|---|
| **pluto-review** | `/pluto-review` | Functional equivalence with Charon Go; parity matrix; test coverage gaps |
| **security-review** | — | Auth bypass, resource exhaustion, key-material handling, DoS vectors |
| **rust-style** | `/rust-style` | Idiomatic Rust; memory orderings; error handling patterns; naming |
| **code-quality** | — | Concurrency correctness; state-machine completeness; resource lifecycle |

Each agent must return findings as JSON objects:
```json
{
  "file": "crates/foo/src/bar.rs",
  "line": 42,
  "severity": "bug|major|minor|nit",
  "title": "short title",
  "body": "detailed explanation with code snippets if helpful"
}
```

## Step 3 — Deduplicate and assess

Merge the four finding lists. For each finding:

- If the same issue is raised by multiple agents, merge into one finding
  (use the most detailed body).
- Assign a final severity: `bug` → `major` → `minor` → `nit`.
- Prefix the comment body with **`nit:`** if severity is `nit`.
- Verify every `file` path and `line` number against the actual diff before
  posting — do not guess.

## Step 4 — Post inline comments via GitHub review API

Build a single JSON payload and post it in **one** API call:

```bash
gh api repos/NethermindEth/pluto/pulls/$PR/reviews \
  --method POST \
  --input /tmp/review_payload.json \
  --jq '{id:.id, state:.state, url:.html_url}'
```

Payload shape:
```json
{
  "commit_id": "<head-sha>",
  "body": "<overall-assessment — see Step 5>",
  "event": "APPROVE | REQUEST_CHANGES | COMMENT",
  "comments": [
    {
      "path": "crates/foo/src/bar.rs",
      "line": 42,
      "side": "RIGHT",
      "body": "comment text"
    }
  ]
}
```

Rules for comments:
- One comment per finding. Do not batch multiple issues into one comment.
- Use `line` + `side: "RIGHT"` for new/modified lines (additions).
- Use `side: "LEFT"` only for deleted lines.
- If `line` is unavailable or ambiguous, omit it — the comment lands at the
  file level, which is still useful.
- nit-level findings must start with **`nit:`** in the comment body.

## Step 5 — Overall assessment

Write a 3–5 sentence overall body for the review covering:
1. What the PR does and overall quality signal.
2. A numbered list of **bugs** (must-fix before merge).
3. Summary of major/minor findings.
4. Verdict rationale.

**Verdict rules:**

| Condition | Event |
|---|---|
| Any `bug` severity finding | `REQUEST_CHANGES` |
| Any `major` severity finding | `REQUEST_CHANGES` |
| Only `minor` / `nit` findings | `COMMENT` (leave open for author discretion) |
| No findings or only `nit` | `APPROVE` |

## Output

After the API call succeeds, print:
```
Review posted: <html_url>
Verdict: <APPROVE|REQUEST_CHANGES|COMMENT>
Findings: <N bugs, M major, P minor, Q nits>
```
