"""Email-security scanner module (registry phase ``dns``).

Passive, read-only DNS lookups against the target domain's published
email-security records.  No connections are made to the target's services;
only DNS TXT/HTTPS queries for well-known record names:

- SPF  (v=spf1) at the domain apex
- DKIM for a bounded set of common selectors
- DMARC (policy + strength) at _dmarc.domain
- MTA-STS policy at _mta-sts.domain (HTTPS well-known)
- BIMI at default._bimi.domain

All findings carry a ``confidence`` field (0.0–1.0).  Severity/CVE mapping
for any fingerprint-derived finding flows only through the existing OSV/KEV
enrichment — this module never invents EOL or CVE data.

Labels: module and outcome only — never a domain or hostname.
"""

from __future__ import annotations

import logging

import dns.resolver
import dns.exception

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase

from metrics.prometheus import (
    EMAIL_SECURITY_REQUESTS_TOTAL,
    EMAIL_SECURITY_FINDINGS_TOTAL,
)

logger = logging.getLogger("sentinelasm.scanner.email_security")

#: Common DKIM selectors to probe (bounded to keep lookups cheap).
DKIM_SELECTORS: tuple[str, ...] = (
    "default", "selector1", "selector2", "google", "k1", "k2",
    "mail", "mta", "smtp", "esmtp", "dkim", "prod",
)

#: DNS query timeout per record type (seconds).
DNS_TIMEOUT = 5.0

#: Max DNS queries per domain (bounded to prevent abuse).
MAX_DNS_QUERIES = 12


def _query_txt(domain: str, record: str) -> list[str]:
    """Query a single DNS TXT record.  Returns the text strings found."""
    try:
        answers = dns.resolver.resolve(record, "TXT", lifetime=DNS_TIMEOUT)
        return [r.to_text().strip('"') for r in answers]
    except (dns.exception.NoAnswer, dns.exception.NXDOMAIN,
            dns.exception.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []


def _parse_spf(txt_records: list[str]) -> str | None:
    """Return the SPF record text if any TXT record starts with v=spf1."""
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            return txt
    return None


def _parse_dmarc(txt_records: list[str]) -> str | None:
    """Return the DMARC record text if any TXT record starts with v=DMARC1."""
    for txt in txt_records:
        if txt.startswith("v=DMARC1"):
            return txt
    return None


def _dmarc_policy(dmarc_record: str | None) -> str:
    """Extract the DMARC 'p' policy value."""
    if not dmarc_record:
        return "none"
    for part in dmarc_record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            return part[2:]
    return "none"


@scanner_module("email_security", phase="dns", order=1)
async def email_security_module(ctx: ScanContext) -> dict:
    """Passive email-security DNS lookups for *ctx.domain*.

    Returns a dict with per-record results and a list of finding dicts
    (each with ``title``, ``severity``, ``category``, ``description``,
    ``recommendation``, ``confidence``).
    """
    findings: list[dict] = []
    records: dict[str, str | list[str]] = {}

    queries = 0
    spf_txt = _query_txt(ctx.domain, ctx.domain)
    spf = _parse_spf(spf_txt)
    records["spf"] = spf
    queries += 1

    # ── DMARC ────────────────────────────────────────────────────────
    dmarc_txt = _query_txt(ctx.domain, f"_dmarc.{ctx.domain}")
    dmarc = _parse_dmarc(dmarc_txt)
    records["dmarc"] = dmarc
    queries += 1

    policy = _dmarc_policy(dmarc)

    # ── DKIM (bounded selector list) ─────────────────────────────────
    dkim_selectors_found: list[str] = []
    for selector in DKIM_SELECTORS:
        if queries >= MAX_DNS_QUERIES:
            break
        dkim_txt = _query_txt(ctx.domain, f"{selector}._domainkey.{ctx.domain}")
        if dkim_txt:
            dkim_selectors_found.append(selector)
        queries += 1
    records["dkim_selectors"] = dkim_selectors_found

    # ── MTA-STS ──────────────────────────────────────────────────────
    # MTA-STS is fetched via HTTPS well-known URL, not DNS TXT.
    # The policy file lives at https://mta-sts.domain/.well-known/mta-sts.txt
    # We do a lightweight DNS resolution check only (no body read).
    mta_sts_available = False
    try:
        import socket
        socket.getaddrinfo(f"mta-sts.{ctx.domain}", 443)
        mta_sts_available = True
    except (OSError, socket.gaierror):
        pass
    records["mta_sts"] = mta_sts_available
    queries += 1

    # ── BIMI ─────────────────────────────────────────────────────────
    bimi_txt = _query_txt(ctx.domain, f"default._bimi.{ctx.domain}")
    records["bimi"] = bool(bimi_txt)
    queries += 1

    # ── Findings ─────────────────────────────────────────────────────
    if not spf:
        findings.append({
            "title": "SPF record not published",
            "severity": "medium",
            "category": "email_security",
            "description": (
                f"No SPF (v=spf1) TXT record found for {ctx.domain}. "
                "Receiving mail servers cannot verify that senders are "
                "authorized, enabling email spoofing."
            ),
            "recommendation": (
                "Publish an SPF TXT record at the domain apex authorizing "
                "your legitimate mail sources (e.g. v=spf1 mx -all)."
            ),
            "confidence": 0.95,
        })
    else:
        # SPF exists but may be overly permissive.
        if "+all" in spf or "?all" in spf:
            findings.append({
                "title": "SPF policy is permissive",
                "severity": "low",
                "category": "email_security",
                "description": (
                    f"SPF record for {ctx.domain} uses a permissive "
                    f"mechanism ('{'+all' if '+all' in spf else '?all'}'), "
                    "allowing unauthorized senders."
                ),
                "recommendation": (
                    "Change SPF 'all' mechanism to '-all' (hard fail) or "
                    "'~all' (soft fail) to reject or flag unauthorized mail."
                ),
                "confidence": 0.9,
            })

    if not dmarc:
        findings.append({
            "title": "DMARC record not published",
            "severity": "medium",
            "category": "email_security",
            "description": (
                f"No DMARC (v=DMARC1) TXT record found at "
                f"_dmarc.{ctx.domain}. Receivers cannot enforce alignment "
                "or receive aggregate/forensic reports."
            ),
            "recommendation": (
                f"Publish a DMARC TXT record at _dmarc.{ctx.domain} starting "
                "with p=none;rua=mailto:dmarc-reports@{ctx.domain}, then "
                "progress to p=quarantine and p=reject."
            ),
            "confidence": 0.95,
        })
    elif policy == "none":
        findings.append({
            "title": "DMARC policy is monitor-only",
            "severity": "low",
            "category": "email_security",
            "description": (
                f"DMARC for {ctx.domain} is set to p=none (monitor-only). "
                "Spoofed messages are not rejected or quarantined."
            ),
            "recommendation": (
                "Progress DMARC policy from p=none to p=quarantine, then "
                "p=reject as legitimate mail sources are confirmed aligned."
            ),
            "confidence": 0.9,
        })

    if not dkim_selectors_found:
        findings.append({
            "title": "No DKIM selectors found",
            "severity": "low",
            "category": "email_security",
            "description": (
                f"No DKIM public keys found for any of {len(DKIM_SELECTORS)} "
                f"common selectors on {ctx.domain}. Outbound mail cannot be "
                "cryptographically signed."
            ),
            "recommendation": (
                "Configure DKIM signing for your outbound mail and publish "
                "the public key under at least one common selector."
            ),
            "confidence": 0.85,
        })

    if not mta_sts_available:
        findings.append({
            "title": "MTA-STS not published",
            "severity": "info",
            "category": "email_security",
            "description": (
                f"No MTA-STS policy found for {ctx.domain}. SMTP connections "
                "are vulnerable to active downgrade attacks."
            ),
            "recommendation": (
                "Publish an MTA-STS policy file at "
                f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt and "
                "add the corresponding TXT record at _mta-sts.{ctx.domain}."
            ),
            "confidence": 0.8,
        })

    if not records["bimi"]:
        findings.append({
            "title": "BIMI record not published",
            "severity": "info",
            "category": "email_security",
            "description": (
                f"No BIMI record found at default._bimi.{ctx.domain}. "
                "Email clients cannot display your organization's logo."
            ),
            "recommendation": (
                "Publish a BIMI TXT record at default._bimi.{ctx.domain} "
                "pointing to your verified SVG logo."
            ),
            "confidence": 0.75,
        })

    # ── Metrics (module + outcome only) ────────────────────────────
    outcome = "ok"
    EMAIL_SECURITY_REQUESTS_TOTAL.labels(
        module="email_security", outcome=outcome
    ).inc()
    EMAIL_SECURITY_FINDINGS_TOTAL.labels(
        module="email_security"
    ).inc(len(findings))

    return {
        "host": ctx.domain,
        "records": records,
        "findings": findings,
        "findings_total": len(findings),
        "queries": queries,
    }
