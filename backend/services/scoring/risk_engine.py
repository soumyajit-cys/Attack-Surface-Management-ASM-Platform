import json
import os
import requests
from datetime import datetime, timezone
from functools import lru_cache

from utils.logger import logger

SEVERITY_BASE_SCORE = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 1.0,
}

CRITICALITY_MULTIPLIER = {
    "prod": 1.5,
    "production": 1.5,
    "staging": 1.2,
    "stage": 1.2,
    "dev": 1.0,
    "development": 1.0,
    "test": 0.8,
}

EXPOSURE_MULTIPLIER = {
    "internet": 1.5,
    "internal": 0.8,
    "dmz": 1.2,
    "unknown": 1.0,
}

TIME_DECAY_HALF_LIFE_DAYS = 30

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CACHE_PATH = "/tmp/cisa_kev_cache.json"
CISA_KEV_TTL_HOURS = 24


def calculate_risk(
    base_severity: str,
    exposure: str = "internet",
    asset_criticality: str = "dev",
    finding_age_days: float = 0,
    is_kev: bool = False,
    confidence: float = 0.8,
) -> float:
    base = SEVERITY_BASE_SCORE.get(base_severity.lower(), 2.0)

    exposure_mult = EXPOSURE_MULTIPLIER.get(exposure.lower(), 1.0)
    criticality_mult = CRITICALITY_MULTIPLIER.get(asset_criticality.lower(), 1.0)

    score = base * exposure_mult * criticality_mult * confidence

    if finding_age_days > 0:
        decay = 0.5 ** (finding_age_days / TIME_DECAY_HALF_LIFE_DAYS)
        score *= (0.3 + 0.7 * decay)

    if is_kev:
        score *= 1.5

    score = min(score, 10.0)

    return round(score, 1)


def get_finding_age_days(created_at) -> float:
    if not created_at:
        return 0
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    return (now - created_at).total_seconds() / 86400


def is_cisa_kev(cve_id: str) -> bool:
    kev_list = _fetch_cisa_kev()
    return cve_id.upper() in kev_list


@lru_cache(maxsize=1)
def _fetch_cisa_kev() -> set:
    try:
        if os.path.exists(CISA_KEV_CACHE_PATH):
            with open(CISA_KEV_CACHE_PATH) as f:
                cache = json.load(f)
            cached_at = datetime.fromisoformat(cache["cached_at"])
            if (datetime.now(timezone.utc) - cached_at).total_seconds() < CISA_KEV_TTL_HOURS * 3600:
                return set(cache["cves"])

        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        cves = set()
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cveID", "").upper()
            if cve:
                cves.add(cve)

        with open(CISA_KEV_CACHE_PATH, "w") as f:
            json.dump({
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "cves": list(cves),
            }, f)

        logger.info("Fetched %d CVEs from CISA KEV catalog", len(cves))
        return cves

    except Exception as exc:
        logger.warning("Failed to fetch CISA KEV catalog: %s", exc)
        if os.path.exists(CISA_KEV_CACHE_PATH):
            try:
                with open(CISA_KEV_CACHE_PATH) as f:
                    cache = json.load(f)
                return set(cache.get("cves", []))
            except Exception:
                pass
        return set()


def recalculate_asset_risk_score(db, asset_id: int) -> float:
    from models.finding import Finding
    from models.asset import Asset
    from models.risk_score import RiskScore

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return 0.0

    findings = db.query(Finding).filter(
        Finding.asset_id == asset_id,
        Finding.organization_id == asset.organization_id,
    ).all()

    import logging
    logging.warning(f"DEBUG recalculate_asset_risk_score: asset_id={asset_id}, asset_org={asset.organization_id}, findings_count={len(findings)}")
    for f in findings:
        logging.warning(f"  Finding: {f.title}, org={f.organization_id}, severity={f.severity}, asset_id={f.asset_id}")

    # Also check all findings for this asset_id regardless of org
    all_findings = db.query(Finding).filter(Finding.asset_id == asset_id).all()
    logging.warning(f"  All findings for asset_id={asset_id}: {len(all_findings)}")
    for f in all_findings:
        logging.warning(f"    Finding: {f.title}, org={f.organization_id}")

    if not findings:
        return 0.0

    total_score = 0.0
    count = 0

    for finding in findings:
        age_days = get_finding_age_days(finding.created_at)
        kev = False
        if finding.category == "vulnerability" and "CVE-" in finding.title.upper():
            import re
            match = re.search(r"CVE-\d{4}-\d+", finding.title.upper())
            if match:
                kev = is_cisa_kev(match.group(0))

        score = calculate_risk(
            base_severity=finding.severity,
            exposure="internet",
            asset_criticality=asset.criticality,
            finding_age_days=age_days,
            is_kev=kev,
            confidence=0.8,
        )
        total_score += score
        count += 1

    avg_score = total_score / count if count > 0 else 0.0

    existing = db.query(RiskScore).filter(RiskScore.asset_id == asset_id).first()
    if existing:
        existing.score = round(avg_score, 1)
        existing.updated_at = datetime.now(timezone.utc)
    else:
        db.add(RiskScore(
            asset_id=asset_id,
            score=round(avg_score, 1),
            exposure=EXPOSURE_MULTIPLIER["internet"],
            severity=SEVERITY_BASE_SCORE.get("medium", 5.0),
            confidence=0.8,
        ))

    return round(avg_score, 1)