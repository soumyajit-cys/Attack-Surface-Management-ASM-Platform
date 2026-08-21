# SentinelASM Risk Scoring Model

## Overview

This document describes the risk scoring methodology used by SentinelASM to prioritize findings and assets. The model combines multiple factors to produce a normalized risk score (0-10) for each finding and an aggregate score per asset.

## Scoring Formula

### Finding-Level Risk Score

```
Finding Risk = Base Severity × Exposure × Asset Criticality × Confidence × Time Decay × KEV Boost
```

Where:
- **Base Severity**: CVSS-like base score mapped from finding severity
- **Exposure**: Network exposure context (internet-facing vs internal)
- **Asset Criticality**: Business criticality tag on the asset
- **Confidence**: Detection confidence (default 0.8)
- **Time Decay**: Reduces score as findings age without resolution
- **KEV Boost**: 1.5× multiplier if finding maps to CISA Known Exploited Vulnerability

### Asset-Level Risk Score

```
Asset Risk = Mean(Finding Risks) across all open findings for the asset
```

## Factor Definitions

### Base Severity (CVSS-like mapping)

| Severity | Base Score | Description |
|----------|------------|-------------|
| critical | 9.0 | Immediate threat, active exploitation likely |
| high | 7.0 | Significant vulnerability, exploitable |
| medium | 5.0 | Moderate risk, requires attention |
| low | 2.0 | Minor issue, defense-in-depth |
| info | 1.0 | Informational, no direct risk |

### Exposure Context

| Exposure | Multiplier | Description |
|----------|------------|-------------|
| internet | 1.5 | Directly internet-facing |
| dmz | 1.2 | In DMZ, partially exposed |
| unknown | 1.0 | Default/external scan perspective |
| internal | 0.8 | Internal network only |

### Asset Criticality

| Criticality | Multiplier | Description |
|-------------|------------|-------------|
| prod / production | 1.5 | Production systems, customer-facing |
| staging / stage | 1.2 | Pre-production, staging environments |
| dev / development | 1.0 | Development environments (default) |
| test | 0.8 | Test/ephemeral environments |

### Time Decay

Findings lose relevance over time if not addressed. The decay follows a half-life model:

```
Time Decay Factor = 0.3 + 0.7 × (0.5 ^ (age_days / 30))
```

- At day 0: factor = 1.0 (no decay)
- At day 30: factor ≈ 0.65
- At day 90: factor ≈ 0.39
- Asymptotic floor: 0.3 (findings never fully decay)

This ensures stale findings don't dominate risk posture while never completely disappearing.

### CISA KEV Boost

If a finding's title or description contains a CVE ID that appears in the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), a 1.5× multiplier is applied.

The KEV catalog is fetched from the official CISA JSON feed and cached locally for 24 hours. This allows offline operation after initial fetch.

## Example Calculations

### Example 1: Critical RCE on Production Internet-Facing Server

```
Base: 9.0 (critical)
Exposure: 1.5 (internet)
Criticality: 1.5 (prod)
Confidence: 0.8
Age: 0 days (decay = 1.0)
KEV: No

Score = 9.0 × 1.5 × 1.5 × 0.8 × 1.0 = 16.2 → capped at 10.0
```

### Example 2: Medium Finding on Development Server, 60 Days Old

```
Base: 5.0 (medium)
Exposure: 1.0 (unknown)
Criticality: 1.0 (dev)
Confidence: 0.8
Age: 60 days (decay = 0.3 + 0.7 × 0.5^(60/30) = 0.3 + 0.7 × 0.25 = 0.475)
KEV: No

Score = 5.0 × 1.0 × 1.0 × 0.8 × 0.475 = 1.9
```

### Example 3: High Finding on Staging, Matches CISA KEV

```
Base: 7.0 (high)
Exposure: 1.2 (dmz)
Criticality: 1.2 (staging)
Confidence: 0.8
Age: 15 days (decay ≈ 0.78)
KEV: Yes (1.5×)

Score = 7.0 × 1.2 × 1.2 × 0.8 × 0.78 × 1.5 = 9.45
```

## Implementation Notes

### Finding Age

The finding age is calculated from `created_at` timestamp. For findings created before this model was deployed, age defaults to 0.

### CVE Extraction

CVE IDs are extracted from finding titles using regex `CVE-\d{4}-\d+`. This matches standard CVE format (e.g., CVE-2024-12345).

### Caching

The CISA KEV catalog is cached at `/tmp/cisa_kev_cache.json` with a 24-hour TTL. If the feed is unavailable, the stale cache is used. If no cache exists, KEV boost is disabled.

### Asset Criticality

Set via the `criticality` column on the `assets` table. Default is `dev`. Should be updated by asset owners to reflect true business impact.

### Exposure Determination

Currently defaults to `internet` for all scanned assets (since ASM focuses on internet-facing attack surface). Future enhancement: integrate network topology data to classify internal vs external assets.

## Score Interpretation

| Score Range | Risk Tier | Action |
|-------------|-----------|--------|
| 8.0 - 10.0 | Critical | Immediate remediation required |
| 6.0 - 7.9 | High | Remediate within 7 days |
| 4.0 - 5.9 | Medium | Remediate within 30 days |
| 2.0 - 3.9 | Low | Address in next maintenance window |
| 0.0 - 1.9 | Info | Track for awareness |

## Future Enhancements

1. **Exploitability Metrics**: Integrate EPSS (Exploit Prediction Scoring System) scores
2. **Threat Intelligence**: Incorporate active exploitation reports from threat feeds
3. **Business Context**: Link assets to business units/applications for contextual prioritization
4. **Custom Weights**: Allow per-organization tuning of factor weights
5. **Asset Relationships**: Propagate risk through dependency graphs (e.g., compromised LB → backend risk)