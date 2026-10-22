# Contributor workflow

This repository uses a manual VS Code / Codex Review workflow. A task is one coherent, independently testable outcome.

## PLANNED PR

1. Verify the repository identity, target branch, and clean working tree. Fetch `origin/main` and create a dedicated branch from it.
2. Implement the requested outcome with meaningful regression tests for substantive Python changes. Keep changes focused and prefer systemic fixes over workarounds.
3. Run `scripts/ci.sh` before publication. Fix failures; never disable or weaken checks to obtain a green result.
4. Commit and push the branch, then open a ready PR. Verify its repository, base, branch, and remote HEAD against the intended commit.
5. Evaluate GitHub Actions and Codex Review for the **current HEAD**. Request Codex Review if available and not already running for that HEAD. Address applicable P1/P2 findings on the same branch, using the FIX FEEDBACK loop.
6. Report any pending, failed, stale, or unavailable gate accurately. Never merge automatically.

## FIX FEEDBACK

1. Stay on the existing PR branch. Read current-HEAD Actions results and Codex comments/reactions; obsolete feedback is not approval.
2. Fix applicable findings with regression tests. Run `scripts/ci.sh`, commit, and push to the same branch.
3. Verify the new remote HEAD. Wait for its Actions checks and request a new Codex Review only if one is not already running for that HEAD.
4. Repeat until all applicable Actions jobs pass and current-HEAD Codex Review has no unresolved actionable P1/P2 findings, or report a genuine blocker. A generic completed review is not a bot thumbs-up; record a current thumbs-up separately when available. Never merge automatically.

## Repository invariants

- Infrastructure diagnostics remain read-only. Do not add arbitrary remote shell execution or change production servers, routers, or credentials.
- The server-side SSH dispatcher must independently authorize every diagnostic operation. Inspector must not access the Docker socket.
- Never commit real secrets, tokens, private keys, private inventory, or infrastructure-specific configuration to this public repository or its tests and logs. Ordinary tests need no production credentials.
- Do not disable, bypass, or weaken CI, tests, or security controls. Avoid unnecessary complexity.
- All substantive Python changes need regression tests. Measure production Python line and branch coverage, identify gaps, and work toward 100%; 100% coverage is a goal, not an enforced current gate.
- Do not commit to or force-push `main`. Human authorization is required to merge.
