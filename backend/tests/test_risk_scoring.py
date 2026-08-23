from datetime import datetime, timedelta, timezone

from models.asset import Asset
from models.finding import Finding
from models.risk_score import RiskScore
from services.scoring.risk_engine import (
    calculate_risk,
    get_finding_age_days,
    is_cisa_kev,
    recalculate_asset_risk_score,
    SEVERITY_BASE_SCORE,
    EXPOSURE_MULTIPLIER,
    CRITICALITY_MULTIPLIER,
    TIME_DECAY_HALF_LIFE_DAYS,
)


def test_calculate_risk_base_severity():
    for severity, base_score in SEVERITY_BASE_SCORE.items():
        score = calculate_risk(
            base_severity=severity,
            exposure="unknown",
            asset_criticality="dev",
            finding_age_days=0,
            is_kev=False,
            confidence=1.0,
        )
        expected = base_score
        assert score == expected, f"{severity}: got {score}, expected {expected}"


def test_calculate_risk_exposure_multiplier():
    base = calculate_risk("medium", "unknown", "dev", 0, False, 1.0)
    for exposure, mult in EXPOSURE_MULTIPLIER.items():
        score = calculate_risk("medium", exposure, "dev", 0, False, 1.0)
        expected = round(base * mult, 1)
        assert score == expected, f"{exposure}: got {score}, expected {expected}"


def test_calculate_risk_criticality_multiplier():
    base = calculate_risk("medium", "unknown", "dev", 0, False, 1.0)
    for crit, mult in CRITICALITY_MULTIPLIER.items():
        score = calculate_risk("medium", "unknown", crit, 0, False, 1.0)
        expected = round(base * mult, 1)
        assert score == expected, f"{crit}: got {score}, expected {expected}"


def test_calculate_risk_time_decay():
    score_day0 = calculate_risk("high", "internet", "prod", 0, False, 1.0)
    score_day30 = calculate_risk("high", "internet", "prod", 30, False, 1.0)
    score_day90 = calculate_risk("high", "internet", "prod", 90, False, 1.0)

    assert score_day30 < score_day0
    assert score_day90 < score_day30

    decay_30 = 0.3 + 0.7 * (0.5 ** (30 / TIME_DECAY_HALF_LIFE_DAYS))
    expected_30 = round(7.0 * 1.5 * 1.5 * 1.0 * decay_30, 1)
    assert score_day30 == expected_30


def test_calculate_risk_kev_boost():
    score_no_kev = calculate_risk("medium", "internet", "prod", 0, False, 1.0)
    score_kev = calculate_risk("medium", "internet", "prod", 0, True, 1.0)

    assert score_kev == round(score_no_kev * 1.5, 1)


def test_calculate_risk_confidence():
    score_full = calculate_risk("medium", "unknown", "dev", 0, False, 1.0)
    score_half = calculate_risk("medium", "unknown", "dev", 0, False, 0.5)

    assert score_half == round(score_full * 0.5, 1)


def test_calculate_risk_cap_at_10():
    score = calculate_risk("critical", "internet", "prod", 0, True, 1.0)
    assert score <= 10.0


def test_get_finding_age_days_none():
    assert get_finding_age_days(None) == 0


def test_get_finding_age_days_datetime():
    created = datetime.now(timezone.utc) - timedelta(days=5)
    age = get_finding_age_days(created)
    assert 4 <= age <= 5


def test_get_finding_age_days_string():
    created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    age = get_finding_age_days(created)
    assert 9 <= age <= 10


def test_recalculate_asset_risk_score_no_findings(db):
    from models.asset import Asset
    from models.organization import Organization

    org = Organization(name="Test Org Risk")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="test.example.com", criticality="dev")
    db.add(asset)
    db.commit()

    score = recalculate_asset_risk_score(db, asset.id)
    assert score == 0.0


def test_recalculate_asset_risk_score_with_findings(db):
    from models.asset import Asset
    from models.organization import Organization

    org = Organization(name="Test Org Risk 2")
    db.add(org)
    db.flush()

    asset = Asset(organization_id=org.id, name="test2.example.com", criticality="prod")
    db.add(asset)
    db.flush()

    for sev in ["critical", "high", "medium"]:
        db.add(Finding(
            organization_id=org.id,
            asset_id=asset.id,
            title=f"Test {sev} finding",
            severity=sev,
            category="test",
        ))
    db.commit()

    score = recalculate_asset_risk_score(db, asset.id)
    assert score > 0


def test_is_cisa_kev_cache():
    cve1 = "CVE-2024-12345"
    cve2 = "CVE-2024-99999"

    result1 = is_cisa_kev(cve1)
    result2 = is_cisa_kev(cve2)

    assert isinstance(result1, bool)
    assert isinstance(result2, bool)