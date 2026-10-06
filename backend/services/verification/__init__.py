"""Domain ownership verification (Phase 1, task 1.1).

DNS-TXT challenges reuse :mod:`utils.ssrf_guard`; the HTTP-file method and
the scan-gating helpers live in :mod:`services.verification.verification_service`.
Outbound HTTP fetching here is deliberately narrow (validated-IP + Host
header, manual 3-hop redirects); task 1.3 consolidates it into the shared
hardened connect helper.
"""
