"""Structured logging setup. Production operators need to grep/aggregate
logs (CloudWatch, Datadog, whatever), which means one JSON object per line,
not Python's default free-text format -- and it means every log line that
touches a specific tenant or request should carry that context, not just a
message string a human has to parse.

Deliberately minimal: no external logging library, just stdlib `logging`
with a JSON formatter. A real deployment can swap this for structlog or
ship stdout straight into a log aggregator that parses JSON lines directly
-- either way, this is the baseline that makes that possible at all."""
from __future__ import annotations
import json
import logging
import os
import sys
import time


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": round(time.time(), 3),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything attached via logger.info(..., extra={"tenant_id": ...})
        # rides along in the JSON line rather than being lost or needing
        # string interpolation into the message itself.
        for key, value in record.__dict__.items():
            if key in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging():
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # Quiet the noisiest third-party loggers down to warnings unless the
    # operator explicitly wants verbose output.
    for noisy in ("httpx", "httpcore", "hpack"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
