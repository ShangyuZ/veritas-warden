"""Integration tests for the Unix-socket server."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from warden.server import handle_client, _serve

_SOCK_COUNTER = 0


def _short_sock_path() -> str:
    global _SOCK_COUNTER
    _SOCK_COUNTER += 1
    return f"/tmp/wdn_test_{_SOCK_COUNTER}.sock"


async def _send_recv(socket_path: str, payload: dict) -> dict:
    reader, writer = await asyncio.open_unix_connection(socket_path)
    writer.write(json.dumps(payload).encode())
    await writer.drain()
    data = await reader.read(65536)
    writer.close()
    return json.loads(data.decode())


@pytest.fixture
async def warden_server():
    """Start a temporary warden server on a short /tmp socket path."""
    socket_path = _short_sock_path()
    task = asyncio.create_task(_serve(socket_path))
    await asyncio.sleep(0.05)
    yield socket_path
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    Path(socket_path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_server_allow_echo(warden_server):
    result = await _send_recv(warden_server, {
        "command": "echo hello",
        "session_id": "s1",
        "origin": "user",
        "trusted": True,
    })
    assert result["outcome"] == "allow"


@pytest.mark.asyncio
async def test_server_block_rm(warden_server):
    result = await _send_recv(warden_server, {
        "command": "rm -rf /",
        "session_id": "s2",
        "origin": "external",
        "trusted": False,
    })
    assert result["outcome"] == "block"
    assert result["rule_id"] == "block_destructive"


@pytest.mark.asyncio
async def test_server_escalate_pip(warden_server):
    result = await _send_recv(warden_server, {
        "command": "pip install malware",
        "session_id": "s3",
        "origin": "external",
        "trusted": False,
    })
    assert result["outcome"] == "escalate"


@pytest.mark.asyncio
async def test_server_block_sudo(warden_server):
    result = await _send_recv(warden_server, {
        "command": "sudo rm -rf /var/log",
        "session_id": "s-sudo",
        "origin": "external",
        "trusted": False,
    })
    assert result["outcome"] == "block"
    assert result["rule_id"] == "block_privilege_escalation"


@pytest.mark.asyncio
async def test_server_audit_log_created(warden_server):
    import tempfile
    import warden.audit as audit_mod
    from warden.models import Decision, Outcome, Provenance, OriginType
    from warden.normalizer import normalize

    log_dir = tempfile.mkdtemp(prefix="warden_audit_test_")
    action = normalize("echo test")
    action.provenance = Provenance(origin=OriginType.USER, trusted=True)
    decision = Decision(outcome=Outcome.ALLOW, rule_id="default_allow", reason="test", action=action)
    audit_mod.write_decision(decision, log_dir=log_dir)

    from datetime import datetime, timezone
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = Path(log_dir) / f"warden-{date_str}.jsonl"
    assert log_file.exists()
    entry = json.loads(log_file.read_text().strip().splitlines()[0])
    assert entry["outcome"] == "allow"
    assert entry["command"] == "echo"


@pytest.mark.asyncio
async def test_server_unknown_origin_defaults_to_external(warden_server):
    result = await _send_recv(warden_server, {
        "command": "pip install pkg",
        "session_id": "s4",
        "origin": "not_a_real_origin",
        "trusted": False,
    })
    assert result["outcome"] == "escalate"


def test_sdk_wrapper_timeout_blocks():
    """SDK wrapper returns block when warden is unreachable (no server on this socket)."""
    from integrations.sdk.wrapper import check_action
    result = check_action("echo hi", socket_path="/tmp/nonexistent_warden.sock")
    assert result["outcome"] == "block"
    assert result["rule_id"] == "connection_error"


@pytest.mark.asyncio
async def test_chain_command_blocked_via_normalizer(warden_server):
    result = await _send_recv(warden_server, {
        "command": "echo ok && rm -rf /tmp/x",
        "session_id": "chain-test",
        "origin": "external",
        "trusted": False,
    })
    assert result["outcome"] == "block"
    assert "rm" in result["reason"]
