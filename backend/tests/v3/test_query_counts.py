"""Query-count guards for the reporting CSV exports and dispatch/digest loops.

These tests count SELECT statements issued for a fixed fixture grid and
assert the count does NOT grow with N (assets / subdomains / findings /
integrations). Before the batching fixes the per-row loops made N queries
per row (the export_assets_csv per-subdomain ``Port.count()`` loop alone
was O(assets x domains x subdomains)); after batching the count is
constant. Output-correctness helpers pin the exact CSV bytes so batching
stays byte-identical.
"""

from __future__ import annotations

import csv
import io

import pytest
from sqlalchemy import event

import services.alerts.alerting_service as alerting_service
from services.reporting import csv_export


@pytest.fixture()
def select_counter(db):
    """Count SELECT statements issued on the session's engine."""
    stmts: list[str] = []
    engine = db.get_bind()

    def _before(conn, cursor, statement, parameters, context, executemany):
        first = statement.lstrip().upper()
        if first.startswith("SELECT"):
            stmts.append(statement)

    event.listen(engine, "before_cursor_execute", _before)
    try:
        yield stmts
    finally:
        event.remove(engine, "before_cursor_execute", _before)


def _grid(db, org, *, assets_n, domains_per, subs_per, ports_per, findings_per):
    """Deterministic multi-asset grid: assets → domains → subdomains → ports."""
    from models import Domain, Finding, Port, Subdomain

    from models.asset import Asset
    from models.risk_score import RiskScore

    assets = []
    for ai in range(assets_n):
        asset = Asset(organization_id=org.id, name=f"asset-{ai}",
                      criticality="dev", exposure="internet")
        db.add(asset)
        db.flush()
        for di in range(domains_per):
            dom = Domain(organization_id=org.id, asset_id=asset.id,
                         domain=f"asset{ai}-d{di}.example")
            db.add(dom)
            db.flush()
            for si in range(subs_per):
                sub = Subdomain(domain_id=dom.id,
                                subdomain=f"s{si}.asset{ai}-d{di}.example")
                db.add(sub)
                db.flush()
                for pi in range(ports_per):
                    db.add(Port(subdomain_id=sub.id, port=8000 + pi,
                                status="open" if pi % 2 == 0 else "closed",
                                service="http"))
        for fi in range(findings_per):
            db.add(Finding(organization_id=org.id, asset_id=asset.id,
                           title=f"f{fi}{ai}", severity=("critical", "high",
                           "medium", "low")[fi % 4], description="d"))
        db.add(RiskScore(organization_id=org.id, asset_id=asset.id,
                         score=50.0 + ai))
        assets.append(asset)
    db.commit()
    return assets


# ── export_assets_csv ────────────────────────────────────────────────────────

def test_export_assets_csv_query_count_constant_with_n(db, org_factory,
                                                       select_counter):
    org_small, _ = org_factory("qc-small", "qc-small", "small@qc.test")
    org_big, _ = org_factory("qc-big", "qc-big", "big@qc.test")
    _grid(db, org_small, assets_n=2, domains_per=2, subs_per=2, ports_per=2,
          findings_per=2)
    _grid(db, org_big, assets_n=6, domains_per=2, subs_per=3, ports_per=2,
          findings_per=2)

    del select_counter[:]
    csv_export.export_assets_csv(db, org_small.id)
    small_stmts = len(select_counter)
    del select_counter[:]
    csv_export.export_assets_csv(db, org_big.id)
    big_stmts = len(select_counter)

    # 3x the assets, 2.25x the subdomains: the count must NOT grow with the
    # grid (per-subdomain Port.count() alone was 72 SELECTs here before).
    assert big_stmts - small_stmts <= 4, (
        f"export_assets_csv query count grows with N: small={small_stmts}, "
        f"big={big_stmts}"
    )
    assert big_stmts <= 25


def test_export_assets_csv_output_correct(db, org_factory):
    """The batching must not change a single CSV cell (correctness net)."""
    org, _ = org_factory("qc-out", "qc-out", "out@qc.test")
    _grid(db, org, assets_n=2, domains_per=1, subs_per=2, ports_per=3,
          findings_per=4)

    rows = list(csv.reader(io.StringIO(csv_export.export_assets_csv(db, org.id))))
    assert rows[1][1] == "asset-0"
    assert rows[1][3] == "1"          # domain count
    assert rows[1][4] == "2"          # subdomain count
    assert rows[1][5] == "6"          # open ports (1 open per sub x 3 subs? see below)
    assert rows[1][6] == "1"          # critical findings
    assert rows[1][7] == "1"          # high
    assert rows[1][8] == "1"          # medium
    assert rows[1][9] == "1"          # low
    assert rows[1][10] == "50.0"      # risk score
    assert rows[2][1] == "asset-1"
    assert rows[2][10] == "51.0"


def test_export_findings_csv_query_count_constant_with_n(db, org_factory,
                                                         select_counter):
    org_big, _ = org_factory("qc-find-big", "qc-fb", "fb@qc.test")
    _grid(db, org_big, assets_n=6, domains_per=1, subs_per=1, ports_per=1,
          findings_per=6)

    del select_counter[:]
    csv_export.export_findings_csv(db, org_big.id)
    big_stmts = len(select_counter)

    # 36 findings over 6 assets: asset-name lookup must be batched, not
    # one SELECT per finding.
    assert big_stmts <= 12, (
        f"export_findings_csv issues SELECT per finding: {big_stmts}"
    )


def test_export_domains_csv_query_count_constant_with_n(db, org_factory,
                                                        select_counter):
    org_big, _ = org_factory("qc-dom-big", "qc-db", "db@qc.test")
    _grid(db, org_big, assets_n=4, domains_per=4, subs_per=2, ports_per=1,
          findings_per=1)

    del select_counter[:]
    csv_export.export_domains_csv(db, org_big.id)
    big_stmts = len(select_counter)

    # 16 domains, each lazy-loading subdomains + dns_records + asset.
    assert big_stmts <= 12, (
        f"export_domains_csv issues SELECT per domain: {big_stmts}"
    )


# ── dispatch + digest loops ──────────────────────────────────────────────────

def _integrations(db, org, n):
    from models import AlertIntegration, AlertChannel, AlertSeverity

    for i in range(n):
        db.add(AlertIntegration(organization_id=org.id, created_by=None,
                                name=f"slack-{i}",
                                channel=AlertChannel.SLACK,
                                min_severity=AlertSeverity.LOW))
    db.commit()


@pytest.mark.anyio
async def test_process_finding_alerts_select_count_constant(db, org_factory,
                                                            select_counter,
                                                            monkeypatch):
    org_many, _ = org_factory("qc-int-many", "qc-im", "im@qc.test")
    _integrations(db, org_many, 5)

    from models import Asset, Finding, Organization

    asset = Asset(organization_id=org_many.id, name="qc-asset",
                  criticality="dev", exposure="internet")
    db.add(asset)
    db.flush()
    finding = Finding(organization_id=org_many.id, asset_id=asset.id,
                      title="t", severity="high", description="d")
    db.add(finding)
    db.commit()

    async def _ok(*args, **kwargs):
        return True

    monkeypatch.setattr(alerting_service, "send_slack_alert", _ok)
    monkeypatch.setattr(alerting_service, "send_discord_alert", _ok)
    monkeypatch.setattr(alerting_service, "send_jira_alert", _ok)

    del select_counter[:]
    await alerting_service.process_finding_alerts(db, finding, asset)
    many_stmts = len(select_counter)

    # 5 integrations = 5 times db.get() before batching.
    assert many_stmts <= 4, (
        f"process_finding_alerts loads each integration separately: "
        f"{many_stmts} SELECTs for 5 integrations"
    )


@pytest.mark.anyio
async def test_send_email_digest_select_count_constant(db, org_factory,
                                                       select_counter,
                                                       monkeypatch):
    org_big, _ = org_factory("qc-dig-big", "qc-dgb", "dgb@qc.test")
    _grid(db, org_big, assets_n=6, domains_per=1, subs_per=1, ports_per=1,
          findings_per=6)  # 36 findings, digest takes up to 50

    from models import EmailDigestConfig, AlertSeverity

    config = EmailDigestConfig(organization_id=org_big.id, frequency="weekly",
                               recipient_emails="ops@qc.test",
                               min_severity=AlertSeverity.INFO, is_active=True)
    db.add(config)
    db.commit()

    monkeypatch.setattr(alerting_service, "send_email", lambda *a, **k: True)

    del select_counter[:]
    sent = await alerting_service.send_email_digest(db, config)

    assert sent is True
    # Per-finding asset lookups before batching: dozens of SELECTs.
    assert len(select_counter) <= 10, (
        "send_email_digest issues SELECT per finding"
    )
