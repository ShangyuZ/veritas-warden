"""Tests for session store — TTL eviction, max-size eviction, state tracking."""
from unittest.mock import patch

import pytest

from common.constants import SESSION_MAX, SESSION_TTL_SECONDS
from warden.session import SessionState, SessionStore


def test_get_or_create_new():
    store = SessionStore()
    session = store.get_or_create("abc")
    assert session.session_id == "abc"
    assert session.action_count == 1


def test_get_or_create_existing():
    store = SessionStore()
    s1 = store.get_or_create("abc")
    s2 = store.get_or_create("abc")
    assert s1 is s2
    assert s2.action_count == 2


def test_sensitive_read_persists():
    store = SessionStore()
    session = store.get_or_create("sess")
    session.sensitive_read = True
    retrieved = store.get_or_create("sess")
    assert retrieved.sensitive_read is True


def test_ttl_eviction():
    store = SessionStore()
    store.get_or_create("old")
    assert len(store) == 1

    # Advance time past TTL
    future = __import__("time").time() + SESSION_TTL_SECONDS + 1
    with patch("warden.session.time.time", return_value=future):
        store.get_or_create("new")  # triggers _evict

    assert "old" not in store._sessions
    assert "new" in store._sessions


def test_max_size_eviction():
    store = SessionStore()
    for i in range(SESSION_MAX):
        store.get_or_create(f"sess-{i}")
    assert len(store) == SESSION_MAX

    # Adding one more should evict the oldest
    store.get_or_create("sess-overflow")
    assert len(store) == SESSION_MAX


def test_action_count_increments():
    store = SessionStore()
    for _ in range(5):
        store.get_or_create("counting")
    assert store.get_or_create("counting").action_count == 6
