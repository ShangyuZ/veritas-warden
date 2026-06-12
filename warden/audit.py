from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import Decision

logger = logging.getLogger(__name__)


def _log_path(log_dir: str) -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Path(log_dir).expanduser() / f"warden-{date_str}.jsonl"


def write_decision(decision: Decision, log_dir: str = "~/.veritas/logs") -> None:
    path = _log_path(log_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": time.time(),
        "outcome": decision.outcome.value,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "command": decision.action.command,
        "raw": decision.action.raw,
        "session_id": decision.action.session_id,
        "origin": (
            decision.action.provenance.origin.value
            if decision.action.provenance
            else None
        ),
        "trusted": (
            decision.action.provenance.trusted
            if decision.action.provenance
            else None
        ),
    }
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.debug("audit: %s %s", decision.outcome.value, decision.action.command)
