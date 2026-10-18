# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for a security problem.**

1. Preferred: open a private **GitHub Security Advisory** on this repository
   (Security tab → "Report a vulnerability"). You will be able to discuss the
   finding privately with the maintainers and receive credit on disclosure.
2. Alternative: email the address in the repository owner's GitHub profile
   with `[security]` in the subject line.

Please include: a description, affected component (backend API, frontend,
docker-compose, CI), reproduction steps or a proof of concept, and your view
of the impact. Do not include real credentials or customer data in reports.

## What we commit to

| Expectation | Target |
|-------------|--------|
| Acknowledgement of your report | 48 hours |
| Triage decision (valid / wontfix / needs more info) | 7 days |
| Fix or mitigation for anything accepted as High or Critical | 30 days |
| Coordinated public disclosure, agreed with you | after the fix ships (tags/releases page or Security Advisory), default 90 days from acceptance |

## Supported versions

Security fixes land on `main` and ship with the next release tag. Only the
most recent published tag (see the Releases page) receives support;
older tags should be upgraded rather than patched.

| Version | Supported |
|---------|-----------|
| latest tag on the Releases page | yes |
| `main` | best-effort |
| anything older | no — upgrade |

## In scope

- The FastAPI backend (`backend/`): auth (JWT, 2FA, lockout), authorization,
  rate limiting, SSRF guards, scanning/enrichment code paths, reports.
- The Single Page Application (`frontend/`): auth flows, client-side rendering
  of tenant data.
- The bundled deployment (`docker-compose.yml`, both Dockerfiles,
  `nginx/nginx.conf`, `scripts/bootstrap.sh`): anything a self-hosting
  operator runs from this repository.
- Supply-chain files: lockfiles, pinned CI actions, `.trivyignore` exceptions.

## Out of scope

- Denial-of-service via sheer traffic volume (no rate limit can fix a
  dedicated flood; we care about *cross-tenant* density-based abuse).
- Volumetric brute force on the live resources of hosts you do not own —
  test against your own instance (the seed/demo script,
  `scripts/seed_demo.py`, exists for this).
- Missing rate limits on endpoints we do not ship (custom forks).
- Anything requiring a compromised host or container (see
  `docs/threat-model.md` "Accepted / out of scope").

## Safe testing

Against your own instance you may: exercise login lockout windows, verify the
`/metrics` gate, attempt tenant-boundary requests across two orgs (the
tenant-matrix tests in `backend/tests/v3/` show how), and check the compose
posture (`docker compose port` banners, `cap_drop`, non-root UID 10001).
Please never modify the dev database (`sentinelasm`); create scratch/demo
databases only.
