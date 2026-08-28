"""Celery application with reliability, DLQ, task routing, and time limits.

Queue topology:
- ``celery``  — default (legacy tasks)
- ``scans``   — scan pipeline tasks
- ``dlq``     — dead-letter queue for permanently failed tasks
"""

from celery import Celery
from kombu import Exchange, Queue

from config import settings

# Importing this module registers the Prometheus Celery signal handlers.
# It must happen before any task is dispatched so *all* workers observe them.
from metrics import celery_metrics  # noqa: F401

celery = Celery(
    "sentinelasm",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["tasks.discovery_tasks", "tasks.scheduler_tasks"],
)

# ── Exchange / Queue definitions ──────────────────────────────────────────────

default_exchange = Exchange("default", type="direct")
scan_exchange = Exchange("scans", type="direct")
dlq_exchange = Exchange("dlq", type="direct")

celery.conf.update(
    # ── Serialisation ────────────────────────────────────────────────────────
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,

    # ── Reliability ──────────────────────────────────────────────────────────
    task_track_started=True,
    task_acks_late=True,                    # ack only after completion/ failure
    task_reject_on_worker_lost=True,        # requeue if worker crashes mid-task
    task_default_retry_delay=60,            # 60 s between retries
    task_max_retries=3,                     # give up after 3 retries
    worker_prefetch_multiplier=1,           # one task at a time per worker
    broker_connection_retry_on_startup=True,

    # ── Time limits ──────────────────────────────────────────────────────────
    task_soft_time_limit=600,               # 10 min → SoftTimeLimitExceeded
    task_time_limit=660,                    # 11 min → SIGKILL

    # ── Result retention ─────────────────────────────────────────────────────
    result_expires=86400,

    # ── Queue routing ────────────────────────────────────────────────────────
    task_queues=(
        Queue("celery", default_exchange, routing_key="celery"),
        Queue("scans", scan_exchange, routing_key="scans"),
        Queue("dlq", dlq_exchange, routing_key="dlq"),
    ),
    task_default_queue="celery",
    task_routes={
        "tasks.discovery_tasks.*": {"queue": "scans"},
        "tasks.scheduler.*": {"queue": "scans"},
        "tasks.scheduler.process_due_scan_policies": {"queue": "scans"},
        "tasks.scheduler.send_due_email_digests": {"queue": "celery"},
    },

    # ── Beat schedule (scan policies + email digests) ────────────────────────
    beat_schedule={
        "process-due-scan-policies": {
            "task": "tasks.scheduler.process_due_scan_policies",
            "schedule": 60.0,       # every minute
            "options": {"queue": "scans"},
        },
        "send-due-email-digests": {
            "task": "tasks.scheduler.send_due_email_digests",
            "schedule": 3600.0,     # hourly
            "options": {"queue": "celery"},
        },
    },

    # ── Dead-letter sink (tasks that exhaust retries land here) ──────────────
    # Individual tasks call ``move_to_dlq()`` on permanent failure.
)

# ── Development overrides ─────────────────────────────────────────────────────

if settings.debug:
    celery.conf.task_always_eager = True
    celery.conf.task_eager_propagates = True


def move_to_dlq(task_name: str, args: tuple, kwargs: dict, exc: Exception) -> None:
    """Publish a failed task payload to the DLQ for later inspection.

    This is a synchronous fire-and-forget: we publish to the ``dlq`` queue
    and let the admin UI / worker drain it later.
    """
    from kombu import producers
    from kombu.serialization import dumps
    import json

    payload = json.dumps({
        "task": task_name,
        "args": args,
        "kwargs": kwargs,
        "error": f"{type(exc).__name__}: {exc}",
    })

    with celery.broker_connection() as conn:
        with producers[conn].acquire(block=True) as producer:
            exchange = Exchange("dlq", type="direct")
            producer.publish(
                payload,
                exchange=exchange,
                routing_key="dlq",
                content_type="application/json",
            )
