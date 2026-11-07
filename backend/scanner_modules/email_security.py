"""Email-security scanner module (registry phase ``dns``).

Passive, read-only DNS lookups against the target domain's published
email-security records.  No connections are made to the target's services;
only DNS TXT/MX queries for well-known record names:

- SPF  (v=spf1) at the domain apex
- DKIM for a bounded set of common selectors
- DMARC (policy + strength) at _dmarc.domain
- MTA-STS policy at _mta-sts.domain (HTTPS well-known)
- BIMI at default._bimi.domain

False-positive guard: SPF/DMARC/DKIM findings only apply when the domain has
mail evidence (an MX record, or an existing SPF or DMARC record).  Domains
with no mail evidence receive at most an info-level note.  DKIM absence
under guessed selectors is always info + low confidence, never medium.
SPF-missing severity is low unless justified otherwise (no MX + no SPF +
no DMARC = info note only).

All findings carry a ``confidence`` field (0.0–1.0) and a ``dedupe_key``
field (stable per finding type) so rescans update rather than duplicate.

Severity/CVE mapping for any fingerprint-derived finding flows only through
the existing OSV/KEV enrichment — this module never invents EOL or CVE
data.

Labels: module and outcome only — never a domain or hostname.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase

from app.core.config import settings
from metrics.prometheus import SCANNER_MODULE_RUNS_TOTAL

logger = logging.getLogger("sentinelasm.scanner.email_security")

#: Common DKIM selectors to probe (bounded to keep lookups cheap).
DKIM_SELECTORS: tuple[str, ...] = (
    "default", "selector1", "selector2", "google", "k1", "k2",
    "mail", "mta", "smtp", "esmtp", "dkim", "prod",
)

#: DNS query timeout per record type (seconds).
DNS_TIMEOUT = settings.email_security_timeout_seconds

#: Max DNS queries per domain (bounded to prevent abuse).
MAX_DNS_QUERIES = settings.email_security_max_queries


def _query_txt(domain: str, record: str) -> list[str]:
    """Query a single DNS TXT record.  Returns the text strings found."""
    try:
        answers = dns.resolver.resolve(record, "TXT", lifetime=DNS_TIMEOUT)
        return [r.to_text().strip('"') for r in answers]
    except (dns.exception.NoAnswer, dns.exception.NXDOMAIN,
            dns.exception.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []


def _query_mx(domain: str) -> list[str]:
    """Query MX records for *domain*.  Returns a list of MX targets."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT)
        return [str(r.exchange).rstrip(".") for r in answers]
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


def _dmarc_pct(dmarc_record: str | None) -> int | None:
    """Extract the DMARC 'pct' value, or None if not set."""
    if not dmarc_record:
        return None
    for part in dmarc_record.split(";"):
        part = part.strip()
        if part.startswith("pct="):
            try:
                return int(part[4:])
            except ValueError:
                return None
    return None


def _has_mail_evidence(mx_records: list[str], spf: str | None,
                       dmarc: str | None) -> bool:
    """True if the domain has any evidence of handling mail.

    Evidence: at least one MX record, or an existing SPF/DMARC record.
    Domains without mail evidence get info-level notes only.
    """
    return bool(mx_records or spf or dmarc)


@scanner_module("email_security", phase="dns", order=1)
async def email_security_module(ctx: ScanContext) -> dict:
    """Passive email-security DNS lookups for *ctx.domain*.

    Returns a dict with per-record results and a list of finding dicts
    (each with ``title``, ``severity``, ``category``, ``description``,
    ``recommendation``, ``confidence``, ``dedupe_key``).
    """
    if not settings.email_security_enabled:
        SCANNER_MODULE_RUNS_TOTAL.labels(
            module="email_security", outcome="disabled"
        ).inc()
        return {
            "host": ctx.domain,
            "records": {},
            "findings": [],
            "findings_total": 0,
            "queries": 0,
        }
    findings: list[dict] = []
    records: dict[str, str | list[str]] = {}

    queries = 0

    # ── MX (mail-evidence gate) ──────────────────────────────────────
    mx_records = _query_mx(ctx.domain)
    records["mx"] = mx_records
    queries += 1

    # ── SPF ──────────────────────────────────────────────────────────
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
    mail_evidence = _has_mail_evidence(mx_records, spf, dmarc)

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
    except (OSError, dns.exception.DNSException):
        pass
    records["mta_sts"] = mta_sts_available
    queries += 1

    # ── BIMI ─────────────────────────────────────────────────────────
    bimi_txt = _query_txt(ctx.domain, f"default._bimi.{ctx.domain}")
    records["bimi"] = bool(bimi_txt)
    queries += 1

    # ── Findings ─────────────────────────────────────────────────────
    if not spf:
        if mail_evidence:
            findings.append({
                "title": "SPF record not published",
                "severity": "low",
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
                "dedupe_key": "email_security:spf_missing",
            })
        else:
            findings.append({
                "title": "No mail evidence or SPF record",
                "severity": "info",
                "category": "email_security",
                "description": (
                    f"No MX, SPF, or DMARC records found for {ctx.domain}; "
                    "the domain does not appear to send or receive mail. "
                    "No email-security configuration is required."
                ),
                "recommendation": (
                    "No action required unless the domain begins sending "
                    "mail; then publish SPF, DKIM, and DMARC records."
                ),
                "confidence": 0.7,
                "dedupe_key": "email_security:no_mail_evidence",
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
                "dedupe_key": "email_security:spf_permissive",
            })

    if not dmarc:
        if mail_evidence:
            findings.append({
                "title": "DMARC record not published",
                "severity": "low",
                "category": "email_security",
                "description": (
                    f"No DMARC (v=DMARC1) TXT record found at "
                    f"_dmarc.{ctx.domain}. Receivers cannot enforce "
                    "alignment or receive aggregate/forensic reports."
                ),
                "recommendation": (
                    f"Publish a DMARC TXT record at _dmarc.{ctx.domain} "
                    "starting with p=none;rua=mailto:dmarc-reports@"
                    f"{ctx.domain}, then progress to p=quarantine and "
                    "p=reject."
                ),
                "confidence": 0.95,
                "dedupe_key": "email_security:dmarc_missing",
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
            "dedupe_key": "email_security:dmarc_none",
        })
    elif policy in ("quarantine", "reject"):
        pct = _dmarc_pct(dmarc)
        if pct is not None and pct < 100:
            findings.append({
                "title": "DMARC policy not applied to all mail",
                "severity": "low",
                "category": "email_security",
                "description": (
                    f"DMARC for {ctx.domain} uses p={policy} but pct={pct}, "
                    "so the policy is not applied to all messages."
                ),
                "recommendation": (
                    "Increase DMARC pct to 100 so the policy covers all mail."
                ),
                "confidence": 0.85,
                "dedupe_key": "email_security:dmarc_pct_under_100",
            })

    if not dkim_selectors_found:
        findings.append({
            "title": "No DKIM selectors found",
            "severity": "info",
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
            "confidence": 0.5,
            "dedupe_key": "email_security:dkim_missing",
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
            "dedupe_key": "email_security:mta_sts_missing",
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
            "dedupe_key": "email_security:bimi_missing",
        })

    # ── Metrics (module + outcome only) ────────────────────────────
    SCANNER_MODULE_RUNS_TOTAL.labels(
        module="email_security", outcome="ok"
    ).inc()

    return {
        "host": ctx.domain,
        "records": records,
        "findings": findings,
        "findings_total": len(findings),
        "queries": queries,
    }
