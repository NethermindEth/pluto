---
name: resolve-pr-comments
description: Check if PR review comments were addressed, resolve answered threads, and approve the PR if none remain. Invoke when asked to verify fixes, resolve comments, or approve a PR after review.
---

## Purpose

Audit review threads on a PR to determine which comments have been addressed by:
1. **Thread replies** — a response was posted in the thread.
2. **Commit diffs** — code changed at the commented location after the comment was posted.

Resolve threads that are answered. Approve the PR if no unresolved threads remain.

---

## Inputs

Required: PR number (e.g. `123`) or full PR URL.  
Optional: repo in `owner/repo` format (defaults to current repo from `gh repo view`).

---

## Step 1 — Fetch review threads

```bash
# Get owner/repo
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
OWNER=$(echo $REPO | cut -d/ -f1)
REPONAME=$(echo $REPO | cut -d/ -f2)

# Fetch all review threads via GraphQL
gh api graphql -F owner="$OWNER" -F repo="$REPONAME" -F pr=<PR_NUMBER> -f query='
query($owner:String!, $repo:String!, $pr:Int!) {
  repository(owner:$owner, name:$repo) {
    pullRequest(number:$pr) {
      headRefOid
      reviewThreads(first:100) {
        nodes {
          id
          isResolved
          path
          line
          comments(first:20) {
            nodes {
              id
              body
              author { login }
              createdAt
              diffHunk
            }
          }
        }
      }
    }
  }
}'
```

For each thread, note:
- `id` — needed to resolve it
- `isResolved` — skip already-resolved threads
- `path` + `line` — file location of the comment
- `comments.nodes[0]` — the original reviewer comment (body, author, createdAt)
- `comments.nodes[1..]` — any replies

---

## Step 2 — Check thread replies

For each **unresolved** thread:

1. Count replies (`comments.nodes.length > 1`).
2. If the PR author replied: the comment was acknowledged.
3. If a reviewer said "resolved", "done", "fixed", "LGTM", "addressed", or similar: mark as answered.
4. If the reply only asks a follow-up question without resolution: treat as **still open**.

Classify each thread as one of:
- `ANSWERED_BY_REPLY` — has a meaningful reply resolving the concern
- `OPEN` — no reply, or reply does not address the concern

---

## Step 3 — Check commit diffs against open comments

For threads still classified as `OPEN`:

```bash
# Get commits on the PR after the comment timestamp
gh pr view <PR_NUMBER> --json commits --jq '.commits[] | {oid:.oid, committedDate:.committedDate}'

# Get the diff for a specific commit
gh api repos/$OWNER/$REPONAME/commits/<SHA> --jq '.files[] | select(.filename == "<path>") | .patch'
```

For each `OPEN` thread:
1. Find commits made **after** `comments.nodes[0].createdAt`.
2. Fetch the diff for the commented file (`path`) from those commits.
3. Compare the diff hunk to the comment's `diffHunk` and `body`:
   - Did the code at that location change?
   - Does the change address what the comment asked for?
4. If yes: reclassify as `ANSWERED_BY_DIFF`.
5. If the file was not touched or the change is unrelated: keep as `OPEN`.

---

## Step 4 — Resolve answered threads

For every thread classified `ANSWERED_BY_REPLY` or `ANSWERED_BY_DIFF`:

```bash
gh api graphql -f query='
mutation($threadId: ID!) {
  resolveReviewThread(input: {threadId: $threadId}) {
    thread { id isResolved }
  }
}' -f threadId="<THREAD_ID>"
```

Report each resolved thread:
```
Resolved: <path>:<line> — <reason: "replied by author" | "addressed in <short-sha>">
```

---

## Step 5 — Approve or report remaining open comments

After resolving answered threads, re-evaluate:

**If no unresolved threads remain:**
```bash
gh pr review <PR_NUMBER> --approve --body "All review comments have been addressed."
```

**If open threads remain**, list them clearly:
```
Still open (<N> threads):
- <path>:<line> by <author> at <timestamp>
  Comment: "<first 120 chars of body>"
  Reason still open: <no reply | reply does not address concern | code not changed>
```

Do NOT approve if any threads are still open.

---

## Output format

Produce a structured summary:

```
PR #<N> — <title>

Review threads: <total>
  Already resolved: <count>
  Answered by reply: <count>
  Answered by diff:  <count>
  Still open:        <count>

Resolved this run:
  ✓ <path>:<line> — <reason>
  ...

Remaining open:
  ✗ <path>:<line> — <reason>
  ...

Outcome: APPROVED | NOT APPROVED (<N> open threads remain)
```

---

## Constraints

- Only resolve threads you have **evidence** are addressed (reply or diff). When uncertain, leave open and explain.
- Do not post comments on the PR unless needed to ask a clarifying question.
- Do not approve if **any** substantive thread is unresolved — even if it looks minor.
- If the PR has zero review threads (or all were already resolved before this run), approve immediately.
