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

## Discovery sources operations (Phase 2)

- crt.sh rate limit (`CRT_SH_RATE_LIMIT_PER_MIN`, default 60/min): global
  Redis token bucket shared by all workers. Fail-closed: if Redis is down,
  crt.sh lookups are skipped (reported as `rate_limit_unavailable`) and the
  scan continues non-fatally. Clear the bucket with
  `DEL ratelimit:discovery:crt_sh` in Redis if it is stuck.
- crt.sh cache TTL (`CRT_SH_CACHE_TTL_SECONDS`, default 3600s): per-domain
  Redis cache key `discovery:crt_sh:cache:<domain>`. Flush with
  `KEYS 'discovery:crt_sh:cache:*' | xargs redis-cli DEL` when you need
  fresh CT-log data.
- crt.sh down / degraded: discovery continues with the remaining providers;
  the scan is NOT failed. `truncated=true` on the scan record / API
  response indicates results were capped by
  `MAX_SUBDOMAINS_PER_SOURCE_PER_SCAN` (default 500 per source).
- DNS brute-force is **active** discovery (queries the target's DNS), bounded
  by `DNS_BRUTE_WORDLIST` (~20 names) and `DNS_BRUTE_CONCURRENCY` (10). It is
  subject to the same scope/verification gating as port/SSL scanning: an
  unpinned target (no verified IP) is skipped, never probed via fresh DNS.

## Email-security scanner operations (Phase 3)

- `EMAIL_SECURITY_ENABLED` (default `true`): set `false` to disable the
  email-security discovery phase entirely. Disabled modules report
  `outcome=disabled` in `sentinelasm_scanner_module_runs_total` and produce
  no findings.
- `EMAIL_SECURITY_TIMEOUT_SECONDS` (default 5.0): per-DNS-query timeout.
- `EMAIL_SECURITY_MAX_QUERIES` (default 12): caps DKIM selector probing.
  Increase only if you need to probe more selectors; each additional query
  adds latency to the discovery phase.
- All lookups are **passive DNS only** (SPF, DKIM, DMARC, MTA-STS, BIMI).
  No connections are made to target services. Results are gated by mail
  evidence: domains with no MX, SPF, or DMARC records receive an info-level
  note only. SPF/DMARC/DKIM findings require mail evidence.
- Findings carry `confidence` (0.0–1.0) and `dedupe_key` fields. Rescans
  update existing findings by `dedupe_key` rather than creating duplicates.
- Severity/CVE mapping flows only through existing OSV/KEV enrichment — this
  module never invents EOL or CVE data.

## Subdomain takeover scanner operations (Phase 3, module 2)

- `SUBDOMAIN_TAKEOVER_ENABLED` (default `true`): set `false` to disable the
  takeover discovery phase entirely. Disabled modules report
  `outcome=disabled` in `sentinelasm_scanner_module_runs_total` and produce
  no findings.
- `SUBDOMAIN_TAKEOVER_TIMEOUT_SECONDS` (default `10.0`): per-DNS/HTTP query
  timeout for takeover lookups.
- `SUBDOMAIN_TAKEOVER_MAX_CONCURRENCY` (default `10`): max concurrent
  takeover lookups per scan.
- `SUBDOMAIN_TAKEOVER_MAX_HOSTS_PER_SCAN` (default `100`): max subdomains
  checked for takeover per scan; exceeded hosts are truncated and reported
  via `truncated=true` on the scan record.
- `SUBDOMAIN_TAKEOVER_MAX_REDIRECTS` (default `3`): max HTTP redirects
  followed during takeover confirmation; each hop is re-validated through
  the SSRF pin.
- `SUBDOMAIN_TAKEOVER_MAX_BODY_BYTES` (default `65536`): max response body
  bytes read during takeover confirmation.
- All outbound connections go through the SSRF pin (`utils.egress`).
  Path A (DNS-only NXDOMAIN confirmation) makes no connections to target
  services. Path B (HTTP confirmation) does a GET / to the subdomain's own
  resolved IP with `Host=<subdomain>`; TLS verification is relaxed — see
  the threat model for details.
- Fingerprint data lives in `backend/scanner_modules/takeover_fingerprints.json`,
  sourced from can-i-take-over-xyz. Providers marked
  `verified_claimable: false` are carried through from the source but never
  produce findings.
- Findings carry `confidence` (≤ 0.85) and `dedupe_key`
  (`subdomain_takeover:<provider_id>:<hostname>`). Rescans update existing
  findings by `dedupe_key` rather than creating duplicates.
- Severity is static per finding type (`high` for claimable providers,
  `medium` for edge-case providers) — not derived from OSV/KEV enrichment.

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
