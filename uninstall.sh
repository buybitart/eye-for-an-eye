#!/usr/bin/env sh
# Eye for an Eye — remove it from Linux.
#
# The companion to `install.sh` at the top level, and like it, a door rather than
# an implementation: it hands over to `scripts/uninstall.sh`. P18 §19, §54.
#
#   sh uninstall.sh            remove the program, keep your settings and records
#   sh uninstall.sh --purge    remove the program AND delete your settings,
#                              your database and your secret. This cannot be undone.
#   sh uninstall.sh --help     every option
#
# It never changes your firewall.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
UNINSTALLER="$HERE/scripts/uninstall.sh"

if [ ! -f "$UNINSTALLER" ]; then
  printf 'Error: %s\n' "cannot find scripts/uninstall.sh next to this file." >&2
  exit 1
fi

exec sh "$UNINSTALLER" "$@"
