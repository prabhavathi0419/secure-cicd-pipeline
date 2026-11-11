"""Structured (JSON) logging that never records secrets.

WHY: Logs are widely readable and long-lived. We log only metadata
(method, path, status, duration) - never request bodies, headers, passwords or tokens.
"""
import json
import logging
import sys

SENSITIVE_KEYS = {"password", "token", "authorization", "secret", "access_token"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = "[REDACTED]" if key.lower() in SENSITIVE_KEYS else value
        return json.dumps(payload)


def setup_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("app")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **fields: object) -> None:
    logger.info(msg, extra={"extra_fields": fields})
