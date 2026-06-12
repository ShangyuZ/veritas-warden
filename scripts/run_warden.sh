#!/usr/bin/env bash
set -euo pipefail

SOCKET_PATH="${WARDEN_SOCKET_PATH:-$HOME/.veritas/warden.sock}"
LOG_DIR="${WARDEN_LOG_DIR:-$HOME/.veritas/logs}"

mkdir -p "$LOG_DIR"

exec warden serve --socket-path "$SOCKET_PATH" --log-dir "$LOG_DIR"
