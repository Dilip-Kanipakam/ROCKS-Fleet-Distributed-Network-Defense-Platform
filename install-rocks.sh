#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo "Run this installer as your normal account. It will request sudo only when installing system services." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ROCKS installer only supports Linux hosts." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required to install ROCKS." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1 || ! systemctl show-environment >/dev/null 2>&1; then
  echo "An active systemd manager is required for the one-command service installation." >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for installing systemd units. Install sudo or ask your system administrator." >&2
  exit 1
fi

if ! python3 - <<'PY'
import sys
if sys.version_info[:2] < (3, 10):
    raise SystemExit(1)
PY
then
  echo "ROCKS requires Python 3.10 or newer." >&2
  exit 1
fi

if [[ -e .venv && ! -x .venv/bin/python ]]; then
  echo "An incomplete .venv already exists; it was left untouched. Rename or repair it, then rerun this installer." >&2
  exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
  VENV_TEMP="$(mktemp -d "$ROOT_DIR/.rocks-venv.XXXXXX")"
  trap 'rm -rf "$VENV_TEMP"' EXIT
  if ! python3 -m venv "$VENV_TEMP"; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "Python venv support is missing; installing the Debian/Ubuntu python3-venv package." >&2
      sudo apt-get install -y python3-venv
      python3 -m venv "$VENV_TEMP"
    else
      echo "Python venv support is missing. Install your distribution's Python venv package and rerun." >&2
      exit 1
    fi
  fi
  mv "$VENV_TEMP" "$ROOT_DIR/.venv"
  trap - EXIT
fi

if ! "$ROOT_DIR/.venv/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)'; then
  echo "The existing .venv uses Python older than 3.10; it was left untouched. Recreate it with a supported Python version, then rerun." >&2
  exit 1
fi

if ! "$ROOT_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  echo "Repairing pip inside .venv."
  "$ROOT_DIR/.venv/bin/python" -m ensurepip --upgrade
fi

echo "Installing ROCKS and its Python dependencies into .venv."
"$ROOT_DIR/.venv/bin/python" -m pip install -e "$ROOT_DIR"
if ! "$ROOT_DIR/.venv/bin/python" -c 'import rocks; import fastapi; import scapy'; then
  echo "ROCKS package validation failed after dependency installation." >&2
  exit 1
fi
"$ROOT_DIR/.venv/bin/rocks" --version

export ROCKS_CONFIG_PATH="${ROCKS_CONFIG_PATH:-$ROOT_DIR/config/config.yaml}"
exec "$ROOT_DIR/.venv/bin/rocks" install "$@"