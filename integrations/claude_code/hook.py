#!/usr/bin/env python3
"""Veritas Warden — PreToolUse hook for Claude Code.

This script intercepts every Bash tool call Claude Code makes and asks
the Warden daemon whether to allow it.  Install it once and every agent
session is automatically guarded.

INSTALL
-------
Add to your Claude Code settings (~/.claude/settings.json):

  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash",
          "hooks": [
            {
              "type": "command",
              "command": "python /path/to/veritas-warden/integrations/claude_code/hook.py"
            }
          ]
        }
      ]
    }
  }

BEHAVIOUR
---------
  ALLOW     → exit 0   (Claude proceeds normally)
  BLOCK     → exit 2   (Claude Code surfaces the block reason to the model)
  ESCALATE  → exit 2   (same; model must seek explicit user approval)

CONFIGURATION
-------------
  WARDEN_SOCKET_PATH   Override the default socket path (~/.veritas/warden.sock)
  WARDEN_FAIL_OPEN     Set to "1" to allow commands when Warden is unreachable.
                       Default is fail-closed (blocked when Warden is down).
  WARDEN_STRICT        Set to "1" to hard-block ESCALATE outcomes in addition
                       to BLOCK outcomes.  Default escalation exits 2 regardless,
                       but this makes the reason message explicitly restrictive.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make the project importable when invoked directly (without pip install -e).
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from common.constants import SOCKET_PATH_DEFAULT
from integrations.sdk.wrapper import check_action


def _block(reason: str) -> None:
    """Exit with code 2 so Claude Code blocks the tool call."""
    print(json.dumps({"decision": "block", "reason": reason}))
    sys.exit(2)


def main() -> None:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)  # malformed input — don't block, let the tool handle it

    tool_name: str = payload.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    tool_input: dict = payload.get("tool_input", {})
    command: str = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    session_id: str = payload.get("session_id", "")
    socket_path: str = os.environ.get("WARDEN_SOCKET_PATH", SOCKET_PATH_DEFAULT)
    fail_open: bool = os.environ.get("WARDEN_FAIL_OPEN", "0") == "1"

    result = check_action(
        command=command,
        session_id=session_id,
        origin="tool",
        trusted=False,
        socket_path=socket_path,
    )

    outcome: str = result["outcome"]
    rule_id: str = result.get("rule_id", "")
    reason: str = result.get("reason", "")

    if outcome == "allow":
        sys.exit(0)

    # Warden unreachable
    if rule_id in ("connection_error", "warden_timeout"):
        if fail_open:
            sys.exit(0)
        _block(
            "Veritas Warden is not running. Start it with `warden serve` or set "
            "WARDEN_FAIL_OPEN=1 to allow commands when Warden is unreachable."
        )

    if outcome == "block":
        _block(f"Veritas Warden blocked this command ({rule_id}): {reason}")

    if outcome == "escalate":
        _block(
            f"Veritas Warden requires approval before running this command "
            f"({rule_id}): {reason}  — ask the user to confirm and re-run with "
            f"explicit approval, or start the server with `warden serve`."
        )

    # Unknown outcome — fail safe
    _block(f"Veritas Warden returned unexpected outcome '{outcome}': {reason}")


if __name__ == "__main__":
    main()
