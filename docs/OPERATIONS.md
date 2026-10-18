# SentinelASM Operations Runbook

Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) and the
[threat model](threat-model.md). Everything here is operator-safe: commands
that touch real data call `scripts/db_guard.sh` and name only
scratch/demo databases or the production DB explicitly labelled as such.

## Database guard and naming rules

`scripts/db_guard.sh` refuses any `DATABASE_URL` whose database name doesn't
start with `scratch_` or `e2e_` (it prints the parsed name and never prints
credentials). `scripts/seed_demo.py` additionally accepts `demo_`. The dev
DB `sentinelasm` is never referenced by automation. Run the guard before
every destructive psql command:

```bash
DATABASE_URL=postgresql://sentinel:sentinelpass@localhost:5432/scratch_<you> bash scripts/db_guard.sh
```

## Backup and restore

Backup is a plain `pg_dump` of the production database — it is the only
durable copy of tenant data (secrets at rest are stored encrypted, so a
confirmed backup that is lost means losing alert-credential ciphertext, not
decryption ability, but losing the actual rows is unrecoverable).

1. Backup (schedule cron-side): `pg_dump -U <owner> -Fd sentinelasm -f /backups/sentinelasm-$(date +%F) && find /backups -maxdepth 1 -type d -mtime +14 -exec rm -rf {} \;`
2. Restore drill: create `scratch_restore_<date>` from the dump, run
   `alembic current` + a read-only smoke query, then drop it.
3. Restore in emergency: stop the backend+worker containers, restore into a
   fresh database (never in-place on the live one), move the old one aside
   (`RENAME TO sentinelasm_broken_<date>`), swap names, restart, verify
   `/health` and `docker compose ps` are healthy.

## Key rotation and SECRETS_ENCRYPTION_KEY

- Alert-credential secrets (webhook `secret`, `jira_api_token`,
  `webhook_url`) are Fernet-encrypted. `SECRETS_ENCRYPTION_KEY` is a
  comma-separated list: first key encrypts, every listed key decrypts.
- Back up the key today (password manager). Losing it makes stored secrets
  unrecoverable — dispatch fails closed with a "check SECRETS_ENCRYPTION_KEY"
  log until a working key returns.
- Rotate: prepend the new key (`NEW,OLD`), run
  `scripts/encrypt_secrets.py --rotate` (use `--dry-run` first to preview
  counts), verify, then drop the old key. Back up the database first; then
  also re-encrypt to drop the old ciphertext format.

## Account repair scripts

Both scripts db-guard their `DATABASE_URL` (scratch_/e2e_ only):

- `scripts/unlock_account.py` — clear a stuck login lockout for an
  administrator/analyst (lockouts cap at 15 min so this is usually
  unnecessary, but it is the fastest path during a lockout-driven outage).
- `scripts/reset_2fa.py` — reset a lost TOTP device: clears the TOTP secret
  and printed recovery codes for the given username; the user re-enrols on
  next login.
- `scripts/encrypt_secrets.py --rotate` — see key rotation above.

All three target a replica/scratch copy first when you can; they accept a
`DATABASE_URL`.

## Upgrading

1. Read the current `CHANGELOG.md` Unreleased section and check for
   "Requires action" notes (migration ordering, env-var additions).
2. On the host: `docker compose pull` (or build from the tag), then run
   `docker compose up -d` — the backend entrypoint applies
   `alembic upgrade head` before booting uvicorn.
3. Verify: `docker compose ps` (all healthy), `curl localhost/health`,
   `docker compose exec backend alembic current` shows the latest revision,
   iterate one scan end-to-end before enabling cron/beat tasks.
4. Rollback: re-tag the previous version's images in `docker compose up`
   (compose reads images by tag+digest; rollback is a redeploy, not a
   database downgrade — Alembic downgrades are NOT automatic).

## SMTP is required for digests and password-reset emails

Setting `SMTP_HOST/_PORT/_USER/_PASSWORD/_FROM` (loopback-only for dev is fine)
is required; without it, sends fail closed/logs an error rather than silently dropping —
password reset just won't deliver.

## Tags and releases

Single branch, tag-cut releases. **Nothing auto-publishes**: `docker-publish`
builds ghcr images + CycloneDX SBOMs only for `v*` tags, so a tag is the
release event.

Ritual (on `main`, no feature branches, no force ops):

1. Confirm `make release-check` is green (make check + audit + `uv lock
   --check` + `npm ci --dry-run`). Never tag on red.
2. Promote the `CHANGELOG.md` `## [Unreleased]` section into
   `## [x.y.z] - <YYYY-MM-DD>` matching the bumped version.
3. Bump the single version source the same commit:
   `VERSION` (repo root). `backend/pyproject.toml` and
   `frontend/package.json` mirror it — `backend/tests/v3/test_release_contract.py`
   fails if they disagree, so one commit carries all three edits.
4. Commit `chore(release): x.y.z` and let the owner push `main` (owner-only).
5. Owner creates the tag off that commit:
   `git tag -a vX.Y.Z -m "SentinelASM vX.Y.Z" && git push origin vX.Y.Z`.
   The tag triggers `docker-publish` (images + CycloneDX SBOM artifacts).
6. Post-tag: `docker compose pull && docker compose up -d` on the host,
   verify with the upgrade checklist above; any fix repeats the ritual
   (never retag) — bump the patch version instead.
