# Summary

<!-- 3–6 lines: what changed and why. Link the issue ("Closes #…"). -->

## How this was verified

<!-- paste the tail of `make check` (exit 0, pass counts). State which
tests are new/updated and which went red before the fix. -->

## Checklist

- [ ] `make check` green on my side (backend + frontend + secrets scan)
- [ ] Tests first where behaviour changed; xfail count still 0
- [ ] New env vars documented (`backend/.env.example` / root `.env.example`
      via `scripts/bootstrap.sh`, README table if user-facing)
- [ ] No secrets, keys, or customer data in the diff or screenshots
      (screenshots come from `scripts/seed_demo.py` fixtures)
- [ ] Single-branch policy respected: no side branches, no force-push,
      no `.git/` edits, no worktree; ready to merge to `main`
- [ ] Version-impacting? Update `CHANGELOG.md` under Unreleased
      (`make release-check` passes)
