from __future__ import annotations

import asyncio
import functools
import json
import logging
from pathlib import Path

from .audit import write_decision
from .models import OriginType, Provenance
from .normalizer import normalize
from .policy import PolicyEngine
from .session import SessionStore
from common.constants import LOG_DIR_DEFAULT, SOCKET_PATH_DEFAULT

logger = logging.getLogger(__name__)

_policy = PolicyEngine()
_sessions = SessionStore()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    log_dir: str = LOG_DIR_DEFAULT,
) -> None:
    try:
        data = await reader.read(65536)
        payload = json.loads(data.decode())

        raw_cmd = payload.get("command", "")
        session_id = payload.get("session_id", "")
        origin_str = payload.get("origin", "external")
        trusted = payload.get("trusted", False)

        origin = (
            OriginType(origin_str)
            if origin_str in OriginType._value2member_map_
            else OriginType.EXTERNAL
        )
        provenance = Provenance(origin=origin, trusted=trusted)

        action = normalize(raw_cmd)
        action.provenance = provenance
        action.session_id = session_id

        session = _sessions.get_or_create(session_id)
        decision = _policy.evaluate(action, session)
        write_decision(decision, log_dir=log_dir)

        response = json.dumps({
            "outcome": decision.outcome.value,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
        })
        writer.write(response.encode())
        await writer.drain()

    except Exception as e:
        logger.exception("Error handling client: %s", e)
        writer.write(
            json.dumps({
                "outcome": "block",
                "rule_id": "error",
                "reason": "Internal warden error.",
            }).encode()
        )
        await writer.drain()
    finally:
        writer.close()


async def _serve(socket_path: str, log_dir: str = LOG_DIR_DEFAULT) -> None:
    path = Path(socket_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    handler = functools.partial(handle_client, log_dir=log_dir)
    server = await asyncio.start_unix_server(handler, path=str(path))
    logger.info("Veritas Warden listening on %s", path)
    async with server:
        await server.serve_forever()


def main(
    socket_path: str = SOCKET_PATH_DEFAULT,
    log_dir: str = LOG_DIR_DEFAULT,
    log_level: int = logging.INFO,
) -> None:
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(_serve(socket_path, log_dir))
