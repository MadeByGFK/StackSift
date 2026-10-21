# Dependency upgrade policy

All Python dependencies are pinned to exact versions (issue #45). The
2026-10-19 red-staging incident (PR #43) was caused by unpinned ranges
silently resolving to fastapi 0.150.0 / starlette 1.9.0, whose changed
upload handling broke the no-file error path with no code change on our
side. Exact pins make every build — CI, Railway staging, Railway
production — install the identical, reviewed set.

## What's pinned where

| File | Installed by | Contents |
|---|---|---|
| `src/web/requirements.txt` | Railway (root dir `src/web`) and CI | Web runtime deps |
| `requirements-dev.txt` | CI | `-r src/web/requirements.txt` + test deps (pytest, playwright) |
| `requirements.txt` | CI | CLI runtime deps (typer, rich) + pytest |

No `.github/workflows/` change is needed: the Tests workflow already
installs these files, so the pins take effect in CI automatically.

## Upgrade path

1. **Who proposes.** Sunny proposes bumps as backlog work during an
   engineering cycle — on a schedule (roughly monthly), when a security
   advisory lands, or when a feature needs a newer version. The founder
   can also request a bump directly.
2. **Branch.** Open a branch from the current `staging/p1` tip. Change
   only the `==` pin(s) in the relevant requirements file — one
   dependency (or one coherent group) per PR.
3. **Test.** Run the full local suite (`python -m pytest tests/
   src/web/tests/`). The PostgreSQL legs skip locally by design; they
   run in CI.
4. **CI.** The PR's Tests workflow must be green, including the real
   PostgreSQL leg. A red run means the new version breaks something:
   either revert the pin or fix the code in the same PR (never silently
   widen the range back).
5. **Review and merge.** Independent review per the engineering
   workflow, then founder merge approval. Merges stay founder-only.

## Security advisories

Same path, expedited: pin bump on a branch, full suite, CI green,
review, founder approval. Never bump directly on `master` or
`staging/p1`, and never loosen a pin to a range to "make CI pass".

## Adding a new dependency

Add it with an exact `==` pin and state the rationale in the PR body.
Prefer the smallest dependency that does the job; vendoring (see
`src/web/app/vendor/VENDORING.md`) is preferred for anything the
diagnostic path must never depend on pip resolving.
