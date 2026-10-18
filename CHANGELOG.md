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
