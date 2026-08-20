from celery import Celery

from config import settings

celery = Celery(
    "sentinelasm",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["tasks.discovery_tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    result_expires=86400,
)

if settings.debug:
    celery.conf.task_always_eager = False