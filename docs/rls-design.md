# Row-Level Security (RLS) — Design Document (NOT IMPLEMENTED)

Status: **design only**. No migration, policy, or application code in this
repository enables Postgres RLS. This document exists so the decision —
whichever way it goes — is made once, with the full cost visible.

## 1. Problem

Multi-tenancy is enforced today in the application layer: every query is
expected to filter by `organization_id` (enforced by repository functions and
characterised by the tenant-matrix tests in `backend/tests/v3/`). The risk RLS
addresses is a **missing WHERE clause**: one forgotten filter in a new service,
task, or script silently leaks or mutates another organisation's rows. RLS
moves that guarantee into the database, where it cannot be forgotten.

## 2. Mechanism

Per-session setting + policy:

```sql
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON assets
  USING (organization_id = current_setting('app.current_org', true)::uuid);
```

Every session must set the tenant before touching data:

```sql
SET app.current_org = '<uuid>';
```

Sessions without the setting (or with an empty string) match
`current_setting(..., true) IS NULL` → policies filter everything out
(fail-closed, no bypass by omission).

### 2.1 Where the setting is set

- **HTTP path**: `backend/app/db/session.py` (`SessionLocal`, the single
  engine/session owner) gains a `before_cursor_execute` hook or the
  `get_db` dependency sets `SET LOCAL app.current_org` from the verified JWT
  claim at request start. `SET LOCAL` is transaction-scoped: it dies with the
  request transaction, so it cannot leak across pooled connections *if*
  sessions are transaction-per-request (they are: `autocommit=False`, one
  session per request via FastAPI dependency).
- **Celery path**: `workers/celery_app.py` task hooks (`task_prerun` /
  `task_postrun`) set the setting from the task's organisation argument. Every
  scan/scheduler task already resolves an `organization_id`; the hooks would
  read it from the task request. Tasks that legitimately span organisations
  (scheduler scanning all orgs' policies) run inside a loop that opens a
  session per org — this is the largest refactor surface.

## 3. Table coverage

Models with `organization_id` (directly covered by a policy on that column):
`alerts`, `alert_integrations`, `assets`, `audit_logs`, `domains`,
`findings`, `organizations`, `reports`, `scan_history`, `scan_policies`,
`users`, `verified_domains`.

Models **without** `organization_id` (child rows reached via join to a parent):

| Table | Parent chain |
|-------|--------------|
| `subdomains` | → `assets.organization_id` |
| `subdomain_ips` | → `subdomains` → `assets` |
| `ports` | → `subdomains` → `assets` |
| `dns_records` | → `subdomains` → `assets` |
| `ssl_results` | → `subdomains` → `assets` |
| `risk_scores` | → `assets` |
| `asset_snapshots` | → `assets` |
| `recovery_codes` | → `users.organization_id` (auth table; arguably should NOT be RLS-filtered — see §6) |

Two options for child tables:

1. **Policy with a subquery** (recommended):
   `USING (asset_id IN (SELECT id FROM assets WHERE organization_id = current_setting(...)))`
   — no schema change; costs a join per policy evaluation.
2. **Denormalise `organization_id` onto the child** — flat, fastest policies,
   but a schema migration on the hottest tables plus a backfill and a
   write-path change wherever children are created.

`users` and `recovery_codes` deserve separate thought: auth flows (login,
refresh, lockout) happen *before* any tenant context exists. A policy on
`users` keyed to `app.current_org` would break login unless the auth code sets
the setting from the user's own row mid-flow — a circular dependency.

## 4. Alembic and scripts

Migrations run as the app's DB role today. Under RLS there are two roles:

- `sentinelasm_app` — subject to policies (`ALTER TABLE ... FORCE ROW LEVEL
  SECURITY` so table-owner shortcuts don't apply).
- `sentinelasm_admin` (bypass role, `BYPASSRLS` attribute) — used ONLY by
  Alembic (`migrations/env.py` swaps its URL via a dedicated env var) and by
  operator scripts (`scripts/encrypt_secrets.py`, `scripts/reset_2fa.py`,
  `scripts/unlock_account.py`). These legitimately cross tenants and cannot
  carry an org context.

The bypass role must be granted narrowly (`GRANT BYPASSRLS` is a cluster-level
attribute on the role, not a per-table grant) and its password kept in the
same secret store as `DATABASE_URL`. Every new script then faces a review
question: app role or bypass role? That is a real operational cost.

## 5. How the tests would prove it

The existing tenant-matrix suite (`tests/v3/test_tenant_matrix.py`, 563+
backend tests) already creates two organisations and asserts isolation through
the API. RLS tests would add a **DB-level** proof:

1. **Policy presence**: a migration test queries `pg_policies` and asserts
   every tenant table has exactly one isolation policy, enabled + forced.
2. **Direct-session bypass attempt**: open two raw sessions, set
   `app.current_org` to org A in one and org B in the other, SELECT the same
   asset id — assert A sees the row and B does not, *without any API layer*.
3. **Unset-setting failure**: a session that never sets the variable sees
   zero rows (fail-closed).
4. **Pooled-connection leakage**: borrow a pooled connection in a request as
   org A, release it, borrow it again as org B, assert no A rows are visible
   (proves `SET LOCAL` + transaction scoping).
5. **Worker path**: enqueue a scan task for org A, assert the worker's session
   cannot read org B rows mid-task.

All five run against a fresh scratch DB (`scripts/db_guard.sh` enforced; the
dev database `sentinelasm` is never touched).

## 6. Performance and rollout risks

- **Policy evaluation cost**: every row of every query evaluates
  `current_setting` + a subquery on child tables. On `subdomains`/`ports`
  (the largest tables in an ASM product) the join-subquery policy is the
  hotspot. Denormalising `organization_id` (option 2 in §3) avoids it but
  costs a migration + backfill on those tables while they are live.
- **Connection pool semantics**: `SET LOCAL` is transaction-scoped; any code
  path that autocommits or leaks a session across requests leaks (or loses)
  tenant context. The NullPool-under-test configuration hides pool bugs from
  the test suite — the leakage test in §5.4 must run against a QueuePool.
- **Operational footguns**: an operator connecting with psql as the app role
  sees *nothing* until they set the variable — confusing, and a plausible
  source of "data is gone" incidents. A bypass role's existence invites
  creeping use ("just this one script…").
- **Migration ordering**: enabling policies and swapping the app role must be
  atomic with the deploy that starts setting `app.current_org`, or the app
  sees empty result sets. A mixed old-code/new-DB window means an outage, so
  this needs a flag-day deploy or a staged "log-only" phase
  (`CREATE POLICY` without `ENABLE` first, flip with `ALTER TABLE ... ENABLE`).
- **Celery fan-out**: scheduler tasks iterate over organisations; each org's
  work needs its own scoped session or the setting must be re-set inside the
  loop. Missing one loop means tasks silently do nothing (fail-closed, but a
  loud production bug).

## 7. Recommendation

**Do not implement RLS now; revisit at the first multi-tenant SaaS customer.**

Why:

1. The isolation property is already characterised by the tenant-matrix tests,
   which fail loudly on any missing `organization_id` filter in the API layer.
   The residual risk is *new code paths* — tasks and scripts — not the API.
2. The two highest-value mitigations are far cheaper than RLS and can ship
   independently: (a) a lint-style test that greps `services/`+`tasks/` for
   `db.query(` without an org filter in the same function, and (b) making
   `organization_id` a non-nullable column with a composite index
   `(organization_id, id)` on every tenant table so the filter is always
   available and always indexed.
3. The cost side is real: a two-role split (with BYPASSRLS creeping into
   scripts), a refactor of every Celery task's session handling, a policy on
   every child table via subquery or a denormalising migration on the largest
   tables, and a flag-day deploy risk. For a product with one deployment and a
   handful of orgs, that is not yet worth it.

Trigger to reopen: a second deployment serving mutually-untrusting customers
on one database, or any audited requirement to demonstrate DB-enforced
isolation. At that point implement §2–§5 in the staged order: policies created
disabled → app sets `SET LOCAL` → tests (§5) green → `ENABLE` + `FORCE` →
drop the app's table-owner shortcut.
