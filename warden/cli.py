from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click

from common.constants import LOG_DIR_DEFAULT, SOCKET_PATH_DEFAULT

_OUTCOME_COLORS = {"allow": "green", "block": "red", "escalate": "yellow"}


@click.group()
def cli() -> None:
    """Veritas Warden — command policy daemon for AI agent workflows."""


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@cli.command("serve")
@click.option(
    "--socket-path",
    default=SOCKET_PATH_DEFAULT,
    show_default=True,
    help="Unix socket path to listen on.",
)
@click.option(
    "--log-dir",
    default=LOG_DIR_DEFAULT,
    show_default=True,
    help="Directory for JSONL audit logs.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def serve(socket_path: str, log_dir: str, verbose: bool) -> None:
    """Start the Veritas Warden daemon.

    The daemon listens on a Unix socket and evaluates every command submitted
    by an AI agent, returning ALLOW / BLOCK / ESCALATE.
    """
    from warden.server import main as _server_main

    level = logging.DEBUG if verbose else logging.INFO
    click.echo(f"Starting Veritas Warden on {Path(socket_path).expanduser()}")
    click.echo(f"Audit logs → {Path(log_dir).expanduser()}")
    _server_main(socket_path=socket_path, log_dir=log_dir, log_level=level)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

@cli.command("check")
@click.argument("command")
@click.option("--trusted", is_flag=True, default=False, help="Mark command as trusted (user-sourced).")
@click.option(
    "--origin",
    default="tool",
    show_default=True,
    type=click.Choice(["user", "tool", "external", "memory"]),
    help="Declared origin of the command.",
)
@click.option(
    "--socket-path",
    default=SOCKET_PATH_DEFAULT,
    show_default=True,
)
@click.option("--session-id", default="cli-check", show_default=True)
def check(
    command: str,
    trusted: bool,
    origin: str,
    socket_path: str,
    session_id: str,
) -> None:
    """Check whether COMMAND would be allowed by the running warden.

    Exits 0 on ALLOW, 1 on BLOCK or ESCALATE.

    \b
    Examples:
      warden check "echo hello"
      warden check "rm -rf /" --origin external
      warden check "pip install requests" --trusted
    """
    from integrations.sdk.wrapper import check_action

    result = check_action(
        command=command,
        session_id=session_id,
        origin=origin,
        trusted=trusted,
        socket_path=socket_path,
    )

    outcome = result["outcome"]
    color = _OUTCOME_COLORS.get(outcome, "white")
    click.secho(f"[{outcome.upper()}]", fg=color, bold=True, nl=False)
    click.echo(f"  rule={result['rule_id']}")
    click.echo(f"       {result['reason']}")

    sys.exit(0 if outcome == "allow" else 1)


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

@cli.command("stats")
@click.option("--log-dir", default=LOG_DIR_DEFAULT, show_default=True)
@click.option("--days", default=7, show_default=True, help="Number of past days to include.")
def stats(log_dir: str, days: int) -> None:
    """Show audit statistics from recent log files."""
    outcome_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    total = 0

    for i in range(days):
        date = datetime.now(timezone.utc) - timedelta(days=i)
        path = Path(log_dir).expanduser() / f"warden-{date.strftime('%Y-%m-%d')}.jsonl"
        if not path.exists():
            continue
        with path.open() as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    outcome_counts[entry.get("outcome", "?")] += 1
                    rule_counts[entry.get("rule_id", "?")] += 1
                    total += 1
                except json.JSONDecodeError:
                    pass

    if total == 0:
        click.echo(f"No audit logs found in {Path(log_dir).expanduser()} for the past {days} days.")
        return

    click.echo(f"\nVeritas Warden — last {days} day(s), {total} total decisions\n")

    click.echo("Outcomes:")
    for outcome, count in outcome_counts.most_common():
        pct = count / total * 100
        color = _OUTCOME_COLORS.get(outcome, "white")
        bar = "█" * int(pct / 5)
        click.secho(f"  {outcome.upper():10}", fg=color, bold=True, nl=False)
        click.echo(f"  {count:5}  ({pct:5.1f}%)  {bar}")

    click.echo("\nTop rules fired:")
    for rule_id, count in rule_counts.most_common(8):
        click.echo(f"  {rule_id:40} {count:5}")


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------

@cli.command("logs")
@click.option("--date", default=None, help="Date YYYY-MM-DD (default: today)")
@click.option(
    "--outcome",
    default=None,
    help="Filter by outcome: allow / block / escalate",
)
@click.option("--log-dir", default=LOG_DIR_DEFAULT, show_default=True)
def logs(date: str | None, outcome: str | None, log_dir: str) -> None:
    """Show warden audit log entries."""
    date_str = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = Path(log_dir).expanduser() / f"warden-{date_str}.jsonl"
    if not path.exists():
        click.echo(f"No log file for {date_str}")
        return
    with path.open() as f:
        for line in f:
            entry = json.loads(line)
            if outcome and entry.get("outcome") != outcome:
                continue
            ts = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).strftime("%H:%M:%S")
            color = _OUTCOME_COLORS.get(entry.get("outcome", ""), "white")
            click.secho(f"[{ts}] ", nl=False)
            click.secho(f"[{entry['outcome'].upper():8}]", fg=color, bold=True, nl=False)
            click.echo(
                f" {entry.get('command', '?')!r:22}  rule={entry['rule_id']}"
            )


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command("status")
@click.option(
    "--socket-path",
    default=SOCKET_PATH_DEFAULT,
    show_default=True,
)
def status(socket_path: str) -> None:
    """Check if the warden server is running."""
    from integrations.sdk.wrapper import check_action

    result = check_action("echo ping", socket_path=socket_path, trusted=True)
    if result.get("outcome") == "allow":
        click.secho("Warden is running and reachable.", fg="green")
    else:
        click.secho(f"Warden not reachable: {result['reason']}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    cli()
