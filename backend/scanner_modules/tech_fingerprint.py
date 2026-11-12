"""Tech fingerprint scanner module (registry phase ``enrichment``).

Passive identification of technologies from headers/TLS/HTML of already-
discovered subdomains. Does NOT make its own outbound connections --
reuses responses already collected by port_scan/ssl_scan header scanning.
Only new outbound connections (if a fingerprint requires fetching a page
not already collected) go through the SSRF-pinned egress helper with
size/redirect/timeouts caps.

Findings carry ``confidence`` (<= 0.85) and ``dedupe_key``
(tech_fingerprint:<technology>:<hostname>). Severity/CVE mapping flows
only through existing OSV/KEV enrichment -- this module never invents
EOL or CVE data.

Labels: module and outcome only -- never a domain or hostname.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.scanning.context import ScanContext
from app.scanning.registry import scanner_module, ScanPhase
from utils.egress import fetch_url_validated

logger = logging.getLogger("sentinelasm.scanner.tech_fingerprint")
