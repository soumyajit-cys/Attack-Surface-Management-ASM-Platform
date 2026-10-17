# SentinelASM Threat Model

Scope: the bundled Docker Compose deployment (single host, fixed
`sentinelnet` subnet 172.28.0.0/16) and the multi-tenant API behind it.
Updated as hardening lands; each row names the control and where it lives.

## Assets

| Asset | Where it lives |
|-------|----------------|
| JWT signing key | `.env` (`JWT_SECRET`), container env |
| Secrets-at-rest key | `.env` (`SECRETS_ENCRYPTION_KEY`), Fernet; alert credentials encrypted in Postgres |
| Postgres data (tenants, findings, users, hashed API keys + TOTP secrets) | named volume `pgdata` |
| Redis (Celery broker, rate-limit + lockout counters, JWT blacklist) | named volume `redisdata`, now password-protected |
| KEV enrichment cache | named volume `kevdata`, mounted at `/kev-cache` (`KEV_CACHE_DIR`) |
| Registry/SMTP/webhook credentials | DB rows, Fernet-encrypted |

## Threats and controls

| # | Threat | Control | Status |
|---|--------|---------|--------|
| T1 | Cross-tenant data read/write via missing `organization_id` filter | Repository-layer scoping + tenant-matrix test suite (`tests/v3/test_tenant_matrix.py`); RLS evaluated, deferred — see `docs/rls-design.md` | Mitigated (app layer), RLS deferred |
| T2 | Credential stuffing / password guessing | Login lockout (per-account + per-IP, exponential backoff, capped 15 min), rate limiting (slowapi), uniform 401 envelope, 503 fail-closed on Redis outage | Mitigated |
| T3 | Token theft (XSS/CSRF) | Short-lived access tokens (15 min), refresh rotation with family burn, session revocation on password change | Mitigated |
| T4 | SSRF from scan targets / integrations | SSRF-pinned outbound fetches, DNS rebinding guard, webhook target allowlist (`WEBHOOK_ALLOWED_PORTS`) | Mitigated |
| T5 | Secrets exfiltration from a compromised container | Fernet at rest; runtime containers run as fixed non-root UID 10001, read-only rootfs, all capabilities dropped, `no-new-privileges` | Mitigated (batch 3) |
| T6 | Supply-chain tampering (deps, base images, CI actions) | uv hashed lockfile + `uv lock --check` gate, `package-lock.json` + `npm ci --dry-run` gate, digest-pinned base images, SHA-pinned Actions with `permissions: contents: read`, gitleaks, Trivy fs/image scans, weekly audit workflow, CycloneDX SBOMs on tags | Mitigated (batches 1–2 + item 1/3) |
| T7 | Redis unauthenticated access on the compose network | `--requirepass` (generated `REDIS_PASSWORD`, never printed), authenticated healthcheck, no host-published port | Mitigated (batch 3) |
| T8 | Container escape / lateral movement | Non-root, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs + tmpfs, pids/mem/cpu limits, single fixed-subnet network, only nginx publishes host ports | Mitigated (batch 3) |
| T9 | Metrics scraping abuse | `/metrics` deny-by-default: bearer token or peer-CIDR admission; nginx returns 404 at the edge | Mitigated |
| T10 | 2FA bypass / replay | TOTP ±1 window, constant-time compare, atomic per-step claim, single-use Redis challenge tokens, recovery codes hashed | Mitigated |
| T11 | Data at rest exposure after DB theft | Alert integration credentials Fernet-encrypted; passwords bcrypt-hashed; API keys + TOTP secrets hashed | Mitigated |
| T12 | Host port exposure of backing services | Postgres and Redis publish no host ports; nginx is the only published surface | Mitigated (batch 3) |

## Accepted / out of scope

- **Single-host trust boundary**: containers on `sentinelnet` trust each
  other; a compromised backend container can reach Postgres/Redis (with
  credentials). Acceptable for the bundled deployment; revisit for
  multi-host/multi-tenant SaaS (RLS + per-service DB roles).
- **Bypass role for migrations/scripts**: any future RLS rollout needs a
  `BYPASSRLS` operator role (see `docs/rls-design.md` §4) — a deliberate,
  audited exception, not a hole.
- **Host kernel / Docker daemon**: assumed trusted; the compose hardening
  limits blast radius, not kernel exploits.
