"""Live scan progress events (publish side).

Every scan lifecycle transition is published to the Redis Stream
``scan:{scan_id}:events`` with ``MAXLEN ~ scan_events_stream_maxlen`` and a
``scan_events_expire_seconds`` TTL. Events carry ONLY data that
``GET /scans/{id}`` already exposes (status, phase name, integer counts,
short static codes, timestamps) — never hostnames of other assets, never
banners, never secrets, never raw error text.

Publishing must never break a scan: every write is wrapped so any failure
only logs a warning naming the exception type and continues. The SSE read
side lives in ``app/api/v1/scans.py``.
"""

from __future__ import annotations

import json

from app.core.config import settings
from utils.logger import logger
from utils.redis_client import get_redis

STREAM_KEY = "scan:{scan_id}:events"

# Terminal event kinds (a stream closes right after them, reader side).
TERMINAL_KINDS = frozenset({"completed", "failed", "skipped"})
PHASES = ("discovery", "scanning", "findings", "changes")

_ALLOWED_COUNT_KEYS = (
    "subdomains_discovered",
    "ports_open",
    "ports_total",
    "ssl_scanned",
    "ssl_issues",
    "header_scanned",
    "header_issues",
    "findings",
    "changes",
)


def stream_key(scan_id: int) -> str:
    return STREAM_KEY.format(scan_id=scan_id)


def build_payload(kind: str, *, phase: str | None = None,
                  counts: dict | None = None, code: str | None = None) -> dict:
    """Whitelist-enforcing payload builder for published events."""
    payload: dict = {}
    if kind in ("queued", "running", "failed", "completed"):
        payload["status"] = kind
    if phase is not None:
        payload["phase"] = phase
    if code is not None:
        payload["code"] = code
    if counts:
        payload["counts"] = {
            key: int(value)
            for key, value in sorted(counts.items())
            if key in _ALLOWED_COUNT_KEYS
        }
    return payload


def publish_scan_event(
    scan_id: int,
    kind: str,
    *,
    phase: str | None = None,
    counts: dict | None = None,
    code: str | None = None,
) -> None:
    """Append one event to the scan's stream; never raises.

    A broken Redis must not fail the scan, so every failure here is a
    logged warning naming the exception type.
    """
    try:
        payload = build_payload(kind, phase=phase, counts=counts, code=code)
        key = stream_key(scan_id)
        r = get_redis()
        r.xadd(
            key,
            {"kind": kind, "data": json.dumps(payload)},
            maxlen=settings.scan_events_stream_maxlen,
            approximate=True,
        )
        r.expire(key, settings.scan_events_expire_seconds)
    except Exception as exc:  # noqa: BLE001 — the WHOLE point is isolation
        logger.warning(
            "Scan %s event publish failed (%s) — scan continues",
            scan_id,
            type(exc).__name__,
        )
