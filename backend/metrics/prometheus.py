from prometheus_client import Counter, Histogram, Gauge, Summary

SCAN_COUNTER = Counter(
    "sentinelasm_scans_total",
    "Total scans executed",
    ["status", "organization"],
)

SCAN_DURATION = Histogram(
    "sentinelasm_scan_duration_seconds",
    "Scan duration in seconds",
    ["organization"],
    buckets=[5, 10, 30, 60, 120, 300, 600, 1800, 3600],
)

SCAN_QUEUE_DEPTH = Gauge(
    "sentinelasm_scan_queue_depth",
    "Number of pending scans in queue",
    ["organization"],
)

FINDINGS_PER_SCAN = Histogram(
    "sentinelasm_findings_per_scan",
    "Number of findings generated per scan",
    ["organization", "severity"],
    buckets=[0, 1, 2, 5, 10, 20, 50, 100],
)

SCAN_ERRORS = Counter(
    "sentinelasm_scan_errors_total",
    "Total scan errors",
    ["organization", "error_type"],
)

SUBDOMAINS_DISCOVERED = Counter(
    "sentinelasm_subdomains_discovered_total",
    "Total subdomains discovered",
    ["organization", "source"],
)

PORTS_SCANNED = Counter(
    "sentinelasm_ports_scanned_total",
    "Total ports scanned",
    ["organization", "status"],
)

SSL_CERTS_ANALYZED = Counter(
    "sentinelasm_ssl_certs_analyzed_total",
    "Total SSL certificates analyzed",
    ["organization", "risk_level"],
)

AUTH_ATTEMPTS = Counter(
    "sentinelasm_auth_attempts_total",
    "Total authentication attempts",
    ["endpoint", "status"],
)

API_REQUESTS = Counter(
    "sentinelasm_api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status"],
)

API_REQUEST_DURATION = Histogram(
    "sentinelasm_api_request_duration_seconds",
    "API request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

ACTIVE_SCANS = Gauge(
    "sentinelasm_active_scans",
    "Number of currently running scans",
    ["organization"],
)

ORGANIZATION_COUNT = Gauge(
    "sentinelasm_organizations_total",
    "Total number of organizations",
)

USER_COUNT = Gauge(
    "sentinelasm_users_total",
    "Total number of users",
    ["organization", "role"],
)

ASSET_COUNT = Gauge(
    "sentinelasm_assets_total",
    "Total number of assets",
    ["organization", "criticality"],
)

FINDING_COUNT = Gauge(
    "sentinelasm_findings_total",
    "Total number of open findings",
    ["organization", "severity"],
)

RISK_SCORE_AVG = Gauge(
    "sentinelasm_risk_score_average",
    "Average risk score across assets",
    ["organization"],
)

CELERY_TASKS = Counter(
    "sentinelasm_celery_tasks_total",
    "Total Celery tasks executed",
    ["task_name", "status"],
)

CELERY_TASK_DURATION = Histogram(
    "sentinelasm_celery_task_duration_seconds",
    "Celery task duration in seconds",
    ["task_name"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
)

REDIS_CONNECTIONS = Gauge(
    "sentinelasm_redis_connections_active",
    "Active Redis connections",
)

DB_CONNECTIONS = Gauge(
    "sentinelasm_db_connections_active",
    "Active database connections",
)

DB_QUERY_DURATION = Histogram(
    "sentinelasm_db_query_duration_seconds",
    "Database query duration in seconds",
    ["query_type"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)