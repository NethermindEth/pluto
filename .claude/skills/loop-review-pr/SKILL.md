---
name: loop-review-pr
description: >
  Iteratively review and fix a Pluto PR until it is "ideal" — drives the
  /review-pr multi-agent pipeline inside /ralph-loop, applying fixes between
  iterations and never posting inline comments. After the loop terminates,
  posts a single summary comment to the GitHub PR with everything that was
  resolved. Invoke as `/loop-review-pr <PR-number|PR-URL>
  [--max-iterations N]`.
---

# Loop Review PR

Orchestrate a self-improving review-and-fix loop for a Pluto PR. The
[[review-pr]] skill is run repeatedly inside [[ralph-loop]]; each iteration
the findings are addressed in code, then the next iteration re-reviews. **No
inline comments are posted to GitHub during the loop.** After completion (or
hitting the iteration cap) post one summary comment.

## 0. Inputs and constants

```text
REPO = NethermindEth/pluto
PR   = <number from arg, or extracted from URL>
MAX_ITERATIONS = <--max-iterations N | default 15>
STATE_DIR = .claude/loop-review-state
STATE     = $STATE_DIR/pr-$PR.md
COMPLETION_PROMISE = "PR_IDEAL"
```

If the user passed a URL like `https://github.com/NethermindEth/pluto/pull/311`,
extract `311`. Reject any other repo.

## 1. Preflight (outer turn — before the loop starts)

Run in parallel:

```bash
gh pr view  "$PR" --repo "$REPO" --json title,body,headRefName,headRefOid,baseRefName,state,isDraft
gh pr diff  "$PR" --repo "$REPO" | head -5  # confirm diff is fetchable
git status --short
```

Then:

1. Refuse if the PR is `MERGED` or `CLOSED`.
2. Check out the PR branch locally:
   ```bash
   gh pr checkout "$PR" --repo "$REPO"
   ```
   Abort if the working tree is dirty (uncommitted changes) — ask the user to
   stash first. Do not run destructive cleanups.
3. Create `$STATE_DIR` if missing. If `$STATE` exists from a prior run, read
   it — it contains the running log of resolved findings; the loop will
   append to it.
4. If `$STATE` does not exist, initialize it:

   ```markdown
   # /loop-review-pr state for PR #<PR>

   - Title: <PR title>
   - Branch: <headRefName>
   - Started: <ISO timestamp>
   - Max iterations: <MAX_ITERATIONS>

   ## Iteration log
   ```

## 2. Build the ralph-loop prompt

The prompt is what ralph-loop will feed back to Claude on every iteration.
Construct it as a single string. Substitute `$PR`, `$REPO`, `$STATE`,
`$MAX_ITERATIONS` literally.

````text
You are running iteration of /loop-review-pr for $REPO PR #$PR.

Goal: keep iterating — review the PR with the same parallel-agent pipeline
as /review-pr, then fix what reviewers flag — until the PR is "ideal".
A PR is ideal when an internal review pass produces NO findings at
severity `bug` or `major`, AND `cargo +nightly fmt --all --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
and `cargo test --workspace --all-features` all succeed.

State file: $STATE
Read it FIRST every iteration. It is the running log of what previous
iterations did. Append to it; never rewrite earlier entries.

## Per-iteration workflow

1. **Read state.** `cat $STATE`. Note the iteration number — increment by 1
   for this iteration. If the prior iteration ended with "PR is ideal",
   verify the claim by re-running the quality gates; if still clean, output
   `<promise>PR_IDEAL</promise>` and stop.

2. **Sync.** `git fetch origin && git status --short && git log --oneline -5`.
   Make sure you are still on the PR branch.

3. **Internal review (no GitHub writes).** Spawn the same four agents in
   parallel as /review-pr Step 2:

   | Agent          | Skill          | Focus                                  |
   |---|---|---|
   | pluto-review   | /pluto-review  | Functional equivalence with Charon Go  |
   | security       | —              | Auth, key material, DoS, exhaustion    |
   | rust-style     | /rust-style    | Idiomatic Rust, error handling, naming |
   | code-quality   | —              | Concurrency, state machines, lifecycle |

   Give each agent the diff (`gh pr diff $PR --repo $REPO`) and the changed
   files on disk. Each agent returns JSON findings as in /review-pr Step 2.

   **You MUST NOT** call any of the following during this loop:
   - `gh pr review`
   - `gh pr comment`
   - `gh api .../pulls/.../reviews`
   - `gh api .../pulls/.../comments`
   - `gh api .../issues/.../comments`
   - any GraphQL `addPullRequestReview*` mutation
   The summary comment is posted by the OUTER turn after the loop ends —
   not from inside the loop.

4. **Dedupe + assess.** Merge findings; assign final severity
   (`bug` > `major` > `minor` > `nit`). Same rules as /review-pr Step 3.

5. **Decide.**
   - If there are zero `bug` and zero `major` findings → go to step 7.
   - Else → step 6.

6. **Fix.** Pick the highest-severity finding, fix the code (and add/update
   tests where the finding is about behavior). Re-run the relevant tests
   for the touched crate. Commit the fix with a focused message — one
   commit per finding is fine, batched commits per file are also fine,
   but DO NOT batch unrelated fixes into one commit. Then append an entry
   to $STATE:

   ```markdown
   ### Iteration <N> — <ISO timestamp>
   - [<severity>] <title> @ <file>:<line>
     Fix: <one-line description of what changed>
     Commit: <sha>
   ```

   After fixing as many findings as you can in this iteration, exit. The
   ralph-loop Stop hook will re-invoke this prompt for the next iteration,
   which will re-review against the new state of the branch.

7. **Quality gates.** Run from `pluto/`:
   ```bash
   cargo +nightly fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```
   If any fail, treat the failure as a `bug` finding and go back to step 6.
   If all pass AND step 5 found no `bug`/`major` findings, append to $STATE:

   ```markdown
   ### Iteration <N> — <ISO timestamp> — IDEAL
   - Internal review: clean (only minor/nit, or none)
   - fmt / clippy / test: green
   ```

   Then output exactly: `<promise>PR_IDEAL</promise>`

## Hard rules

- One PR, one branch. Never switch branches; never rebase onto main inside
  the loop unless a fix explicitly requires it (and then say so in $STATE).
- Do not force-push.
- Do not skip git hooks (no `--no-verify`).
- Do not include a `Co-Authored-By:` trailer in commits — the user has
  explicitly rejected it.
- Do not delete work-in-progress files left by earlier iterations.
- If progress stalls (two consecutive iterations with no new fixes and the
  same findings) — append a `### STALLED` note to $STATE explaining what is
  blocking, then output `<promise>PR_IDEAL</promise>` is FORBIDDEN. Instead
  let the iteration cap end the loop; the outer turn will summarize the
  stall.
````

## 3. Start the loop

Invoke ralph-loop with the prompt above. From the outer turn, call the
ralph-loop slash command (it's the `ralph-loop:ralph-loop` plugin command):

```text
/ralph-loop "<the prompt from §2>" --completion-promise "PR_IDEAL" --max-iterations <MAX_ITERATIONS>
```

Use the Skill tool with `skill: "ralph-loop:ralph-loop"` and pass the prompt
plus flags as args. The loop runs inside the current session; the Stop hook
keeps re-firing the prompt until the completion promise appears or the
iteration cap is hit.

## 4. After the loop ends

When control returns to the outer turn (either the completion promise was
emitted or `--max-iterations` was reached):

1. **Verify gates one more time** from the outer turn (don't trust the loop):
   ```bash
   cd pluto
   cargo +nightly fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```

2. **Push** the accumulated commits to the PR branch:
   ```bash
   git push   # branch already tracks the PR head; no --force
   ```
   If the upstream rejected (someone else pushed) → stop and surface to the
   user; do not force.

3. **Build the summary** from `$STATE`. Group resolved findings by severity
   and reference commits. Compute:
   - `iterations_run` = number of `### Iteration N` headers.
   - `terminated_by` = `completion_promise` | `iteration_cap` | `stall`.
   - `gates` = result of step 1 above.

4. **Post exactly one comment** to the PR:

   ```bash
   gh pr comment "$PR" --repo "$REPO" --body-file /tmp/loop-review-summary.md
   ```

   Body template:

   ```markdown
   ## /loop-review-pr summary

   Ran <iterations_run> review-and-fix iteration(s) against this PR.
   Terminated by: **<terminated_by>**.

   ### Quality gates (final)
   - `cargo fmt`    — <pass|fail>
   - `cargo clippy` — <pass|fail>
   - `cargo test`   — <pass|fail>

   ### Resolved during the loop

   **Bugs (<N>)**
   - <title> — `<file>:<line>` — fix in <commit-sha>

   **Major (<N>)**
   - …

   **Minor (<N>)**
   - …

   **Nits (<N>)**
   - …

   ### Outstanding
   <Any findings the loop chose not to address, or — if terminated by
   iteration_cap / stall — the unresolved items from $STATE, with reasons.>

   ### Verdict
   <One of:
     - "PR is ideal — all bug/major findings resolved, gates green."
     - "Hit iteration cap (<N>) before reaching ideal state — see Outstanding."
     - "Stalled at iteration <N> — see Outstanding for blockers."
   >
   ```

   This is the **only** comment posted to GitHub. No inline review comments.
   No second comment. If the body is empty (no findings resolved, gates
   already green on entry), still post a single one-line "no changes were
   needed" comment so the run is auditable.

5. **Print to the user** the PR URL and a one-line verdict, plus the path
   to `$STATE` if they want to inspect the full log.

## Error & edge cases

- **No findings in iteration 1, gates green** → loop exits immediately with
  `PR_IDEAL`; outer turn posts the "no changes needed" comment.
- **Loop emits the promise but gates fail in the outer verification** →
  re-enter the loop with the failing-gate output prepended; do not post a
  misleading "ideal" summary.
- **User cancels with `/cancel-ralph`** → outer turn still runs §4 with
  `terminated_by: user_cancel` and posts the summary of whatever was done.
- **PR has additional commits pushed by someone else mid-loop** → next
  iteration's `git fetch` will surface it; the loop should rebase only if
  necessary, and the summary should mention it.

## Output

After §4 step 4 succeeds, print:

```text
Loop done: <iterations_run> iteration(s), terminated by <terminated_by>.
Summary comment: <gh pr comment URL>
State log: $STATE
```
