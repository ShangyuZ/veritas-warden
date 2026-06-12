from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class OriginType(str, enum.Enum):
    USER = "user"
    EXTERNAL = "external"
    MEMORY = "memory"
    TOOL = "tool"


@dataclass
class Provenance:
    origin: OriginType
    trusted: bool
    label: str = ""

    @classmethod
    def trusted_user(cls) -> "Provenance":
        return cls(origin=OriginType.USER, trusted=True, label="user")

    @classmethod
    def untrusted_external(cls) -> "Provenance":
        return cls(origin=OriginType.EXTERNAL, trusted=False, label="external")


@dataclass
class CommandComponent:
    """One segment of a chained command (split at &&, ||, ;)."""
    raw: str
    command: str
    args: list[str] = field(default_factory=list)
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)


@dataclass
class Action:
    raw: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    provenance: Optional[Provenance] = None
    session_id: str = ""
    # Non-empty when the raw command contains chain operators (&&, ||, ;).
    # Each entry is one component; the list is in execution order.
    components: list[CommandComponent] = field(default_factory=list)


class Outcome(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass
class Decision:
    outcome: Outcome
    rule_id: str
    reason: str
    action: Action
