"""Security logging that is evidence, not surveillance (brief SS50, SS51).

Logged:      timestamps, event names, check IDs, verdicts, rule names, PIDs, error codes
NEVER logged: URLs, page contents, cookies, tokens, passwords, form data, download
              contents, browsing history

There is NO telemetry of any kind. Nothing in bruhswer sends anything anywhere; these
logs are local files the user can read and delete.
"""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler

from . import config

# Belt and braces: even though callers are not supposed to pass URLs or secrets, the
# formatter redacts anything that looks like one. A logger that leaks is worse than no
# logger, and "the caller should not have done that" is not a control.
_REDACTIONS = (
    (re.compile(r"https?://[^\s\"']+", re.I), "<url-redacted>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email-redacted>"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|cookie|authorization)"
                r"\s*[:=]\s*\S+"), r"\1=<redacted>"),
)


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        for pattern, replacement in _REDACTIONS:
            text = pattern.sub(replacement, text)
        return text


_configured = False


def get_logger(name: str = "bruhswer") -> logging.Logger:
    global _configured
    logger = logging.getLogger("bruhswer")
    if not _configured:
        config.ensure_dirs()
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            config.LOGS / "bruhswer.log", maxBytes=512 * 1024, backupCount=3,
            encoding="utf-8")
        handler.setFormatter(RedactingFormatter(
            "%(asctime)s %(levelname)-7s %(name)s %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False
        _configured = True
    return logger if name == "bruhswer" else logger.getChild(name)
