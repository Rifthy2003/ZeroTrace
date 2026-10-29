"""
Structured logging with secret redaction.

Never log: passwords, session cookies, API keys, auth tokens, or other secrets.
This module provides a logging filter that redacts common secret patterns
before anything reaches a log handler.
"""
import logging
import re
import sys

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(authorization|api[_-]?key|token|secret)\s*[:=]\s*\S+"),
    re.compile(r"(?i)set-cookie:\s*\S+", re.MULTILINE),
    re.compile(r"(?i)bearer\s+[a-z0-9\-_.]+"),
]


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(0).split(":")[0].split("=")[0] + "=[REDACTED]", redacted)
    return redacted


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
        except Exception:
            pass
        return True


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]


scan_logger = logging.getLogger("scanner")
