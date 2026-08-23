import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

from config import settings

correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        correlation_id = correlation_id_var.get()

        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if correlation_id:
            log_data["correlation_id"] = correlation_id

        if hasattr(record, "scan_id"):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, "organization_id"):
            log_data["organization_id"] = record.organization_id
        if hasattr(record, "asset_id"):
            log_data["asset_id"] = record.asset_id
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("sentinelasm")
    logger.setLevel(getattr(logging, settings.log_level.upper()) if hasattr(settings, 'log_level') else logging.INFO)

    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if getattr(settings, 'log_format', 'json') == 'json':
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )

    logger.addHandler(handler)
    logger.propagate = False

    return logger


def get_correlation_id() -> str:
    cid = correlation_id_var.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_var.set(cid)
    return cid


def set_correlation_id(cid: str = None) -> str:
    if cid is None:
        cid = str(uuid.uuid4())
    correlation_id_var.set(cid)
    return cid


def clear_correlation_id() -> None:
    correlation_id_var.set("")


def log_with_context(
    logger: logging.Logger,
    level: int,
    message: str,
    **context: Any,
) -> None:
    extra = {k: v for k, v in context.items() if not k.startswith("_")}
    logger.log(level, message, extra=extra)


logger = setup_logging()