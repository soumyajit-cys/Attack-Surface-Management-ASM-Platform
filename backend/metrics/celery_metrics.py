"""Celery signal handlers that feed the Prometheus ``CELERY_TASKS`` and
``CELERY_TASK_DURATION`` metrics.

Registered once when ``workers.celery_app`` is imported. All signal handlers
are best-effort: metric failures must never break task execution.
"""

from time import perf_counter

from celery import signals as celery_signals

from metrics.prometheus import CELERY_TASKS, CELERY_TASK_DURATION

_TASK_STARTED: dict[str, float] = {}


def _task_id(request):
    if isinstance(request, str):
        return request
    return getattr(request, "id", None) or "unknown"


def on_task_received(*args, **kwargs):
    request = kwargs.get("request") or (args[0] if args else None)
    if request is None:
        return
    task_name = request.name if hasattr(request, "name") else "unknown"
    CELERY_TASKS.labels(task_name=task_name, status="received").inc()


def on_task_prerun(*args, **kwargs):
    request = kwargs.get("task_id") or (args[0] if args else None)
    task = kwargs.get("task") or (args[1] if len(args) > 1 else None)
    task_name = task.name if hasattr(task, "name") else "unknown"
    task_id = request if isinstance(request, str) else _task_id(request)
    CELERY_TASKS.labels(task_name=task_name, status="started").inc()
    _TASK_STARTED[task_id] = perf_counter()


def _record_duration(task_name: str, task_id: str) -> None:
    started = _TASK_STARTED.pop(task_id, None)
    if started is not None:
        CELERY_TASK_DURATION.labels(task_name=task_name).observe(perf_counter() - started)


def on_task_success(*args, **kwargs):
    result = kwargs.get("result") or (args[0] if args else None)
    request = kwargs.get("task_id") or (args[2] if len(args) > 2 else None)
    task = kwargs.get("task") or (args[1] if len(args) > 1 else None)
    task_name = task.name if hasattr(task, "name") else "unknown"
    task_id = request if isinstance(request, str) else _task_id(request)
    CELERY_TASKS.labels(task_name=task_name, status="succeeded").inc()
    _record_duration(task_name, task_id)


def on_task_failure(*args, **kwargs):
    request = kwargs.get("task_id") or (args[0] if args else None)
    task = kwargs.get("task") or (args[1] if len(args) > 1 else None)
    task_name = task.name if hasattr(task, "name") else "unknown"
    task_id = request if isinstance(request, str) else _task_id(request)
    CELERY_TASKS.labels(task_name=task_name, status="failed").inc()
    _record_duration(task_name, task_id)


def register_celery_signal_handlers() -> None:
    """Idempotent registration of all Celery metric signal handlers."""
    celery_signals.task_received.connect(
        on_task_received, weak=False, dispatch_uid="prom.task_received"
    )
    celery_signals.task_prerun.connect(
        on_task_prerun, weak=False, dispatch_uid="prom.task_prerun"
    )
    celery_signals.task_success.connect(
        on_task_success, weak=False, dispatch_uid="prom.task_success"
    )
    celery_signals.task_failure.connect(
        on_task_failure, weak=False, dispatch_uid="prom.task_failure"
    )


register_celery_signal_handlers()