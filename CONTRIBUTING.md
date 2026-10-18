# Contributing to SentinelASM

Thanks for contributing. This repository keeps the process deliberately small
and automated; most of the work is "patch, run `make check`, open a PR".

## Setup (clean clone, one time)

```bash
git clone <your fork> && cd SentinelASM
make setup          # idempotent: creates ./.env + ./backend/.env with generated secrets
# local dev databases are named scratch_*/demo_* only — scripts/db_guard.sh refuses anything else
make dev            # backend on http://localhost:8000 (needs a scratch/democ DB; see README)
npm ci && npm run dev && cd ..   # frontend on http://localhost:5173 (separate terminal, in frontend/)
```

Requirements: Python 3.13, Node 20, a local PostgreSQL and Redis
(`uv` for the backend; see `backend/README`-equivalent notes in
`backend/pyproject.toml`). Before any DB command, run
`DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_yourname bash scripts/db_guard.sh`
to verify the target is a scratch DB.

## Quality gate

**Run `make check` before every commit.** It must exit 0:

- backend: ruff + mypy + pytest (characterization suites, 0 xfail expected)
- frontend: tsc + prettier + vitest + production build
- secrets scan: gitleaks

Never commit secrets; production values go to `.env` (git-ignored, generated
by `scripts/bootstrap.sh`).

## Commit style

- Conventional Commits: `type(scope): short imperative summary`
  (e.g. `fix(auth): constant-time TOTP compare`, `docs(rls): design draft`).
- One focused change per commit; tests for behaviour changes go in the same
  commit when practical.

## Single-branch policy — and what it means for PRs

**Everything lands on `main`. There are no long-lived feature branches.**

- Open the PR, keep it small, expect a fast merge. Do not hold a feature
  branch for days; small PRs are the substitute for long-lived branches.
- There is no `develop` and no release branches: `main` is always releasable;
  release artifacts are built from tags (`v*`) cut off `main`.
- `docker-publish` publishes images only for `v*` tags — a merged PR that
  isn't tagged has not shipped. See `docs/OPERATIONS.md` for the tagging
  ritual.
- Do NOT force-push, rebase history, or edit Git metadata; normal commits
  only.

## PR checklist

1. `make check` passes on your machine.
2. New env vars are documented in `.env.example` (a test enforces Settings
   field coverage) and, for user-facing ones, in README's configuration table.
3. Tests first where the change alters behaviour (red → green).
4. No new branches, no worktrees, no `.git/` edits, no force-push, no push
   (the owner pushes).
5. Anything that copies data out of the codebase must not leave the build:
   use `FIXTURE` data (see `scripts/seed_demo.py` for the pattern).
