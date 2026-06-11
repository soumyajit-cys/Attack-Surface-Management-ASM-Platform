from prometheus_client import Counter

SCAN_COUNTER = Counter(
    "scans_total",
    "Total scans executed"
)
