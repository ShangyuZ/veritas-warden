from __future__ import annotations

import json
import os
import socket

from common.constants import SOCKET_PATH_DEFAULT


def check_action(
    command: str,
    session_id: str = "",
    origin: str = "tool",
    trusted: bool = False,
    socket_path: str = SOCKET_PATH_DEFAULT,
) -> dict:
    """Send an action proposal to the Warden server and return the decision.

    Returns a dict with keys: outcome, rule_id, reason.
    Falls back to blocking with rule_id="connection_error" if the server
    is unreachable (fail-closed by design).
    """
    payload = json.dumps({
        "command": command,
        "session_id": session_id,
        "origin": origin,
        "trusted": trusted,
    }).encode()

    path = os.path.expanduser(socket_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect(path)
        sock.sendall(payload)
        response = sock.recv(65536).decode("utf-8")
        sock.close()
    except socket.timeout:
        sock.close()
        return {
            "outcome": "block",
            "rule_id": "warden_timeout",
            "reason": "Warden did not respond within 5s — blocked for safety.",
        }
    except Exception as e:
        sock.close()
        return {
            "outcome": "block",
            "rule_id": "connection_error",
            "reason": str(e),
        }
    return json.loads(response)
