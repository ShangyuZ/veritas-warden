from __future__ import annotations

import time
from dataclasses import dataclass, field

from common.constants import SESSION_MAX, SESSION_TTL_SECONDS


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    sensitive_read: bool = False
    action_count: int = 0


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def get_or_create(self, session_id: str) -> SessionState:
        self._evict()
        if session_id not in self._sessions:
            if len(self._sessions) >= SESSION_MAX:
                oldest = min(
                    self._sessions,
                    key=lambda k: self._sessions[k].last_active,
                )
                del self._sessions[oldest]
            self._sessions[session_id] = SessionState(session_id=session_id)
        state = self._sessions[session_id]
        state.last_active = time.time()
        state.action_count += 1
        return state

    def _evict(self) -> None:
        now = time.time()
        expired = [
            k
            for k, v in self._sessions.items()
            if now - v.last_active > SESSION_TTL_SECONDS
        ]
        for k in expired:
            del self._sessions[k]

    def __len__(self) -> int:
        return len(self._sessions)
