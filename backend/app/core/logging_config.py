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
    (re.compile(r"(?i)(authorization)\s*:\s*bearer\s+[a-z0-9\-_.]+"), r"\1: Bearer [REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9\-_.]+"), r"Bearer [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s,;\"']+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(authorization|api[_-]?key|token|secret)\s*[:=]\s*([^\r\n,;\"']+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)set-cookie:\s*([^\r\n]+)"), r"Set-Cookie: [REDACTED]"),
    (re.compile(r"(?i)[\"']?(password|passwd|pwd|token|secret|access_token)[\"']?\s*:\s*[\"'][^\"']+[\"']"), r'"\1": "[REDACTED]"'),
]


def redact(text: str) -> str:
    if not text:
        return ""
    redacted = str(text)
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
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
