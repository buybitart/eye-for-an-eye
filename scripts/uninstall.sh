#!/usr/bin/env sh
# Eye for an Eye uninstaller.
#
# By default it removes the program only. Your configuration and your
# database stay on disk. Use --purge if you also want them removed.
#
# It never changes your firewall.

set -eu

MODE="local"
PREFIX=""
DATA_DIR=""
PURGE=0
DRY_RUN=0

say() { printf '%s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '    [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

usage() {
  cat <<'EOF'
Eye for an Eye uninstaller

Usage:
  scripts/uninstall.sh [options]

Options:
  --local        Remove the current user install. This is the default.
  --system       Remove the system install. Needs root.
  --prefix DIR   Program directory to remove.
  --data-dir DIR Data directory. Only removed with --purge.
  --purge        Also delete the configuration, the database and the secret.
                 This deletes your data. It cannot be undone.
  --dry-run      Show every step. Change nothing.
  -h, --help     Show this help and stop.

This script never changes firewall rules. If you added firewall rules by hand,
remove them yourself.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --local) MODE="local" ;;
    --system) MODE="system" ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix needs a directory"; PREFIX="$2"; shift ;;
    --data-dir) [ $# -ge 2 ] || fail "--data-dir needs a directory"; DATA_DIR="$2"; shift ;;
    --purge) PURGE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1 (use --help)" ;;
  esac
  shift
done

if [ "$MODE" = "system" ]; then
  [ "$(id -u)" = "0" ] || fail "--system needs root. Use sudo, or use --local."
  [ -n "$PREFIX" ] || PREFIX="/opt/eye-for-an-eye"
  [ -n "$DATA_DIR" ] || DATA_DIR="/var/lib/eye-for-an-eye"
  BIN_DIR="/usr/local/bin"
else
  [ -n "$PREFIX" ] || PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/eye-for-an-eye"
  [ -n "$DATA_DIR" ] || DATA_DIR="$PREFIX/data"
  BIN_DIR="$HOME/.local/bin"
fi

step "Removing the command link"
if [ -L "$BIN_DIR/eye-for-an-eye" ] || [ -f "$BIN_DIR/eye-for-an-eye" ]; then
  run rm -f "$BIN_DIR/eye-for-an-eye"
else
  say "    Nothing to remove."
fi

step "Removing the program"
if [ -d "$PREFIX/venv" ]; then
  run rm -rf "$PREFIX/venv"
else
  say "    Nothing to remove."
fi

if [ "$PURGE" -eq 1 ]; then
  step "Deleting your data (--purge)"
  say "    $DATA_DIR"
  if [ -d "$DATA_DIR" ]; then
    run rm -rf "$DATA_DIR"
  else
    say "    Nothing to remove."
  fi
  if [ -d "$PREFIX" ]; then
    run rmdir "$PREFIX" 2>/dev/null || say "    $PREFIX is not empty. It was kept."
  fi
else
  step "Your data was kept"
  say "    $DATA_DIR"
  say "    Use --purge to delete it."
fi

say ""
say "Done. The firewall was not changed."
