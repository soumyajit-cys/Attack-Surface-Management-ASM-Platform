# Changelog

All notable changes to SentinelASM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(the single source of the version is the `VERSION` file at the repo root;
`backend/pyproject.toml` and `frontend/package.json` mirror it and tests fail
when they disagree).

## [Unreleased]

### Added

- `docs/openapi.json` + `docs/API.md` regenerated via `make openapi`, with
  drift tests (`backend/tests/v3/test_openapi_docs.py`) that fail when either
  goes stale against the app's routes.
- `docs/ARCHITECTURE.md` and `docs/OPERATIONS.md` runbooks.
- README rewritten: honest feature-status table, Security model summary,
  screenshot placeholders with a capture list, drift-protected
  configuration table (Settings-field coverage test).
- Release contract: `VERSION` file as the single semantic-version source,
  `make release-check` gate, Keep a Changelog-format changelog, and the
  documented tag ritual (`docs/OPERATIONS.md` § Tags and releases) — no tag
  has been cut yet.
- `scripts/seed_demo.py`: fixture-only demo seeding for screenshots (refuses
  anything but `demo_`/`scratch_` databases via `scripts/db_guard.sh`).
- Community files: MIT LICENSE, SECURITY.md (private-advisory reporting),
  CONTRIBUTING.md (single-branch policy), CODE_OF_CONDUCT.md, issue + PR
  templates.

### Changed (Phase 2.1)

- Discovery sources: crt.sh CT-log provider now **fail-closed** on Redis
  outage (skip lookup, report `rate_limit_unavailable`, scan continues);
  per-source cap `max_subdomains_per_source_per_scan` applied with
  deterministic ordering, `truncated=true` + counts on the provider result
  and scan record (`scan_history.discovery_meta`), surfaced in `GET
  /scans/{id}`; new metric outcome `truncated`.
- DNS brute-force relabeled honestly as **active** discovery (bounded
  wordlist ~20 names, concurrency 10, scope/verification gated like
  port/SSL scanning).
- `subdomains` migration adds `sources`, `first_seen`, `last_seen` and a
  unique constraint on `(domain_id, subdomain)`; the upgrade deterministically
  merges pre-existing duplicate rows (oldest kept, sources unioned,
  min/max timestamps, FKs repointed) before creating the constraint.
- Metrics: discovery provider labels are `provider` and `outcome` only
  (`ok | error | rate_limit_unavailable | truncated`) — never a domain or
  hostname.
- Rate limiter: fail-closed when Redis is unreachable (`RATE_LIMIT_FAIL_CLOSED`,
  default `true`): every non-health request answers 429 instead of failing
  open; health checks stay exempt.

### Added (Phase 2.1)

- Egress-abuse test suite (`tests/v3/test_egress_abuse.py`): non-JSON crt.sh
  bodies pass through (parse failure lives in the provider), 5xx returns the
  status as-is (retry/backoff lives in the provider), slow/hanging responses
  time out — all provider-level concerns, never egress-level blocks.

### Added (Phase 3, module 1: email_security)

- `scanner_modules/email_security.py`: passive email-security discovery
  module (registry phase `dns`). SPF, DKIM (bounded selector list), DMARC
  (policy + strength), MTA-STS, BIMI — all read-only DNS lookups, no
  connections to target services.
- Mail-evidence gating: SPF/DMARC/DKIM findings require MX, SPF, or DMARC
  records present; domains without mail evidence receive an info-level note
  only. DKIM absence is info + low confidence, never medium.
- `dedupe_key` on every finding for stable rescan deduplication; findings
  carry `confidence` (0.0–1.0).
- Severity/CVE mapping flows only through existing OSV/KEV enrichment — no
  invented EOL or CVE data.
- `ScanPhase.DNS` and `ScanPhase.FINGERPRINT` added to the pipeline;
  `SCOPE_PHASES` updated (`passive`: discovery + DNS; `active`: + port/SSL/
  header; `full`: + fingerprint).
- `EMAIL_SECURITY_ENABLED`, `EMAIL_SECURITY_TIMEOUT_SECONDS`,
  `EMAIL_SECURITY_MAX_QUERIES` settings (backend `.env.example`, root
  `.env.example`, README config table).
- Single `sentinelasm_scanner_module_runs_total{module,outcome}` counter
  replaces per-module Prometheus counters; label-restriction test updated.
- Frontend: email findings displayed on Findings pages with remediation
  text; vitest coverage (`frontend/src/pages/Settings.test.tsx` +
  `frontend/src/pages/Findings.test.tsx`).

### Added (Phase 2.1)

- Egress-abuse test suite (`tests/v3/test_egress_abuse.py`): non-JSON crt.sh
  bodies pass through (parse failure lives in the provider), 5xx returns the
  status as-is (retry/backoff lives in the provider), slow/hanging responses
  time out — all provider-level concerns, never egress-level blocks.

- `EnrichmentProvider` ORM model + `enrichment_providers` table: per-org
  provider config with Fernet-encrypted API key (`encrypted_api_key`),
  `is_active`, `created_at`/`updated_at`, unique `(organization_id, name)`.
- `backend/app/api/v1/enrichment.py`: admin-only (`enrichment:manage`)
  provider management API — GET lists providers returning only `has_key` /
  `is_active` (never the key); PUT sets/rotates the key + active flag with
  required `acknowledge_data_sharing=true` to enable any third-party
  provider; DELETE removes a provider; all mutations audited.
- `backend/migrations/versions/20261101_0001-7a8b9c0d1e2f_discovery_meta.py`:
  `scan_history.discovery_meta` JSONB column for per-source truncation.
- Frontend Settings UI section for enrichment provider management
  (admin-only) with tenant isolation and key-never-exposed behavior.
- Grafana panels: discovery provider requests by outcome, rate limit
  unavailable, truncated sources.
- docs/ARCHITECTURE.md §8, docs/OPERATIONS.md discovery runbook,
  docs/threat-model.md data flows (crt.sh egress + third-party provider),
  README config table + feature table updated.

### Fixed (Phase 2.1)

- `subdomains` unique constraint no longer fails on duplicate rows: the
  upgrade dedupes deterministically first.


### Security (Phase 0–2 hardening, pre-0.1.0 baseline)

- Container posture: non-root UID 10001, multi-stage builds, digest-pinned
  base images, read-only rootfs with tmpfs and a `kevdata` named volume,
  `cap_drop: ALL`, `no-new-privileges`, resource limits; unprivileged nginx.
- Redis `--requirepass` (generated `REDIS_PASSWORD`, never printed).
- Supply-chain: hashed uv lockfile + frontend `package-lock.json` with
  `make lock`/`make audit`, SHA-pinned GitHub Actions, digest-pinned
  images, gitleaks, Trivy fs + image scans (HIGH/CRITICAL, fixed-only,
  empty `.trivyignore`), weekly read-only audit workflow, CycloneDX SBOMs on
  tag builds.
- Auth: PyJWT HS256, refresh-token family burn, login lockout (per-account
  + per-IP, capped 15 min, uniform 503 fail-closed), TOTP 2FA with recovery
  codes, restricted `enroll_2fa` route, change-password flow.
- `/metrics` deny-by-default (bearer token or CIDR; nginx 404s the path).
- `TRUSTED_PROXIES` peer validation for audit trail integrity.
- Domain-ownership gate before scans (`REQUIRE_DOMAIN_VERIFICATION`).

## [0.1.0] - 2026-10-18

Initial public snapshot: full ASM life cycle (domain verification, subdomain/
port/DNS/SSL discovery, finding synthesis, KEV/OSV scoring), multi-tenant
RBAC, alerting + digest, CSV/PDF reporting, Prometheus metrics, hardened
compose deployment, 589+ backend characterization tests and 28 frontend tests
red-green through `make check`.

[Unreleased]: #unreleased
[0.1.0]: #010---2026-10-18
