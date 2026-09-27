#!/usr/bin/env sh
# Eye for an Eye — install on Linux.
#
# This is the file to run. It does not install anything itself: it hands over to
# `scripts/install.sh`, which is the only installer this project has. P18 §19
# forbids a second implementation of installation logic, and this is why there
# is not one — there is one installer and one door to it.
#
# The door exists because of where people look. A beginner who unpacks the
# release archive, or who opens the repository on GitHub, sees the top level and
# nothing else. Before P18 the top level showed six Windows `.cmd` launchers and
# six `+`-prefixed compatibility shims, and the Linux installer was two
# directories in, which is a poor first screen for the platform that has the
# complete feature set.
#
#   sh install.sh              install for you only, no root
#   sh install.sh --help       every option
#   sudo sh install.sh --system  install for all users
#
# What it never does: it never changes your firewall, never turns on blocking,
# never opens a port, and never starts a service.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$HERE/scripts/install.sh"

if [ ! -f "$INSTALLER" ]; then
  printf 'Error: %s\n' "cannot find scripts/install.sh next to this file." >&2
  printf '%s\n' "Run this from the folder you unpacked, with scripts/ beside it." >&2
  exit 1
fi

exec sh "$INSTALLER" "$@"
