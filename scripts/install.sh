#!/usr/bin/env sh
# Eye for an Eye installer.
#
# What it does:
#   1. finds Python 3.12
#   2. makes a virtual environment
#   3. installs this project into it
#   4. creates a safe first configuration (Shadow Mode, no blocking)
#
# What it never does:
#   - it never changes your firewall
#   - it never turns on blocking or enforcement
#   - it never turns on active probes
#   - it never opens a port to the Internet
#   - it never starts or enables a system service
#
# POSIX sh. Tested with dash and bash.

set -eu

VERSION="2"
MODE="local"
PREFIX=""
DATA_DIR=""
PYTHON=""
WHEEL=""
# P18 §34. production-shadow is the safe first posture: the whole analysis path
# runs, decides and writes evidence, and enforces nothing. The older default,
# "website", leaves the [autonomy] section out entirely, so a machine installed
# with it decided nothing at all — while scripts/install_windows.py had been
# writing production-shadow since P17. Two installers, two different products.
PROFILE="production-shadow"
DRY_RUN=0
RUN_SETUP=1
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

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
Eye for an Eye installer

Usage:
  scripts/install.sh [options]

Options:
  --local              Install for the current user only. No root. This is the default.
  --system             Install for all users. Needs root. Does not start any service.
  --prefix DIR         Where to install the program files.
                       Default (local):  $HOME/.local/share/eye-for-an-eye
                       Default (system): /opt/eye-for-an-eye
  --data-dir DIR       Where to keep the configuration and the database.
                       Default (local):  $HOME/.local/share/eye-for-an-eye/data
                       Default (system): /var/lib/eye-for-an-eye
  --python PATH        Use this Python 3.12 program.
  --wheel FILE         Install this .whl file instead of the source tree.
                       Use this when the machine has no Internet access.
  --profile NAME       First configuration profile: production-shadow, website,
                       sensor, honeypot or lab.
                       Default: production-shadow. It watches, decides and
                       records, and it never blocks. Automatic blocking is a
                       separate thing you switch on yourself, later, on purpose.
  --no-setup           Install the program, but do not create a configuration.
  --dry-run            Show every step. Change nothing.
  -h, --help           Show this help and stop.

After the install:
  eye-for-an-eye setup      choose what to watch
  eye-for-an-eye start      begin Safe Monitoring
  eye-for-an-eye status     see how it is doing

To remove it again:
  scripts/uninstall.sh
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --local) MODE="local" ;;
    --system) MODE="system" ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix needs a directory"; PREFIX="$2"; shift ;;
    --data-dir) [ $# -ge 2 ] || fail "--data-dir needs a directory"; DATA_DIR="$2"; shift ;;
    --python) [ $# -ge 2 ] || fail "--python needs a path"; PYTHON="$2"; shift ;;
    --wheel) [ $# -ge 2 ] || fail "--wheel needs a file"; WHEEL="$2"; shift ;;
    --profile) [ $# -ge 2 ] || fail "--profile needs a name"; PROFILE="$2"; shift ;;
    --no-setup) RUN_SETUP=0 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1 (use --help)" ;;
  esac
  shift
done

case "$PROFILE" in
  production-shadow|website|sensor|honeypot|lab) : ;;
  *) fail "profile must be production-shadow, website, sensor, honeypot or lab" ;;
esac

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

VENV="$PREFIX/venv"

# --- 1. checks -------------------------------------------------------------
step "Checking the system"

[ -f "$SOURCE_DIR/pyproject.toml" ] || fail "run this script from the project checkout"

# P18 §20: say what this computer is before doing anything to it. Linux is the
# platform with the complete feature set; the rest is stated, not implied.
KERNEL="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
say "    System:    $KERNEL $ARCH"
if [ "$KERNEL" != "Linux" ]; then
  say ""
  say "    Note: this is the Linux installer and this computer is $KERNEL."
  say "    Safe Monitoring of a web server's access log should still work."
  say "    Packet capture and automatic blocking are Linux only."
  say ""
fi

# Required commands, named individually so a missing one is a sentence and not a
# later failure inside a subshell.
for needed in mkdir ln cat; do
  command -v "$needed" >/dev/null 2>&1 || fail "the command '$needed' is missing"
done

UV="$(command -v uv 2>/dev/null || true)"

python_ok() {
  [ -x "$1" ] || command -v "$1" >/dev/null 2>&1 || return 1
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)' >/dev/null 2>&1
}

if [ -n "$PYTHON" ]; then
  python_ok "$PYTHON" || fail "$PYTHON is not Python 3.12"
elif python_ok python3.12; then
  PYTHON="python3.12"
elif python_ok python3; then
  PYTHON="python3"
elif [ -n "$UV" ]; then
  PYTHON=""
  say "    Python 3.12 not found on PATH. uv will provide it."
else
  fail "Python 3.12 is required. Install it, or install uv, or use --python PATH."
fi

if [ -n "$WHEEL" ] && [ ! -f "$WHEEL" ]; then
  fail "wheel file not found: $WHEEL"
fi

say "    Mode:      $MODE"
say "    Program:   $PREFIX"
say "    Data:      $DATA_DIR"
say "    Command:   $BIN_DIR/eye-for-an-eye"
if [ -n "$PYTHON" ]; then say "    Python:    $PYTHON"; else say "    Python:    uv managed 3.12"; fi
[ "$DRY_RUN" -eq 1 ] && say "    Dry run:   nothing will change"

# --- 2. directories --------------------------------------------------------
step "Creating directories"
run mkdir -p "$PREFIX" "$DATA_DIR" "$BIN_DIR"

# P18 §20: check we can actually write where we are about to write, and say which
# directory refused rather than failing halfway through an install.
if [ "$DRY_RUN" -eq 0 ]; then
  for directory in "$PREFIX" "$DATA_DIR" "$BIN_DIR"; do
    [ -w "$directory" ] || fail "cannot write in $directory. Check who owns it."
  done
fi

# --- 3. virtual environment ------------------------------------------------
if [ -x "$VENV/bin/python" ]; then
  step "Reusing the virtual environment ($VENV)"
else
  step "Creating the virtual environment ($VENV)"
  if [ -n "$PYTHON" ]; then
    run "$PYTHON" -m venv "$VENV"
  else
    run "$UV" venv --python 3.12 "$VENV"
  fi
fi

# --- 4. install ------------------------------------------------------------
TARGET="${WHEEL:-$SOURCE_DIR}"
step "Installing Eye for an Eye from ${WHEEL:-the source tree}"
if [ -n "$UV" ]; then
  run "$UV" pip install --python "$VENV/bin/python" --upgrade "$TARGET"
elif [ "$DRY_RUN" -eq 1 ] || [ -x "$VENV/bin/pip" ]; then
  # A dry run reports the command it would use; the environment does not exist yet.
  run "$VENV/bin/pip" install --upgrade "$TARGET"
else
  fail "neither uv nor pip is available in $VENV"
fi

# --- 5. command link -------------------------------------------------------
step "Linking the command into $BIN_DIR"
run ln -sf "$VENV/bin/eye-for-an-eye" "$BIN_DIR/eye-for-an-eye"

# --- 6. first configuration ------------------------------------------------
CONFIG="$DATA_DIR/eye-for-an-eye.toml"
if [ "$RUN_SETUP" -eq 0 ]; then
  step "Skipping setup (--no-setup)"
elif [ -f "$CONFIG" ]; then
  step "Configuration already exists. It was not changed."
  say "    $CONFIG"
else
  step "Creating a safe first configuration (profile: $PROFILE)"
  # --config is explicit and --no-questions is deliberate: an installer that
  # stops to ask a question is an installer that hangs when it is run from a
  # script or a package hook. The questions belong to `eye-for-an-eye setup`,
  # which the operator runs next and which this installer tells them to run.
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '    [dry-run] %s\n' "$VENV/bin/eye-for-an-eye setup --profile $PROFILE --config $CONFIG --no-questions"
  else
    ( cd "$DATA_DIR" && "$VENV/bin/eye-for-an-eye" setup --profile "$PROFILE" \
        --config "$CONFIG" --no-questions )
  fi
fi

# --- 6b. the install receipt -----------------------------------------------
# P18 §53. One record of what was installed where, written by the half that
# knows, read by the half that needs to know.
#
# This file exists because P18 ran the documented Linux flow and found the two
# halves disagreeing about one path. The installer wrote the configuration to
# <prefix>/data/eye-for-an-eye.toml; the beginner commands looked only at
# <prefix>/eye-for-an-eye.toml, which is where the Windows installer puts it. So
# a successful install was followed by "a settings file exists — NO", and
# `eye-for-an-eye start` told a Linux user to double-click a Windows .cmd file.
#
# A receipt rather than a matching constant, because --prefix and --data-dir mean
# the answer is a runtime fact, not a compile-time one.
RECEIPT="$PREFIX/install-receipt.json"
REPORT="$PREFIX/install-report.txt"
step "Recording what was installed"
if [ "$DRY_RUN" -eq 1 ]; then
  printf '    [dry-run] %s\n' "write $RECEIPT and $REPORT"
else
  cat > "$RECEIPT" <<EOF
{
  "schema_version": 1,
  "installer": "scripts/install.sh",
  "installer_version": "$VERSION",
  "mode": "$MODE",
  "prefix": "$PREFIX",
  "program": "$VENV",
  "data_dir": "$DATA_DIR",
  "config": "$CONFIG",
  "command": "$BIN_DIR/eye-for-an-eye",
  "profile": "$PROFILE",
  "platform": "$KERNEL $ARCH"
}
EOF
  chmod 644 "$RECEIPT"
  # The support file START_HERE.md and docs/BEGINNER_GUIDE.md both tell people to
  # send. Before P18 only the Windows installer wrote one, so the documented
  # Linux support path asked for a file that was never created.
  {
    say "Eye for an Eye install report"
    say ""
    say "Installer:        scripts/install.sh version $VERSION"
    say "Mode:             $MODE"
    say "System:           $KERNEL $ARCH"
    say "Profile:          $PROFILE"
    say "Program:          $VENV"
    say "Settings file:    $CONFIG"
    say "Data directory:   $DATA_DIR"
    say "Command:          $BIN_DIR/eye-for-an-eye"
    say ""
    say "Automatic blocking: OFF"
    say "Firewall changed:   NO"
    say "Service installed:  NO"
    say ""
    say "This file contains no passwords, no keys and no visitor traffic."
  } > "$REPORT"
  chmod 644 "$REPORT"
  say "    $RECEIPT"
  say "    $REPORT"
fi

# --- 7. what to do next ----------------------------------------------------
say ""
step "Installation complete (installer version $VERSION)"
say ""
say "  Mode:               Safe Monitoring"
say "  Automatic blocking: OFF"
say "  Firewall changed:   NO"
say "  Started:            NO"
say ""
say "Next, two steps:"
say ""
say "  1. Choose what to watch:"
say "       eye-for-an-eye setup"
say ""
say "  2. Start watching:"
say "       eye-for-an-eye start"
say ""
say "To see how it is doing at any time:"
say ""
say "       eye-for-an-eye status"
say ""
say "For the technical view, administrators use:"
say ""
say "       eye-for-an-eye doctor --config $CONFIG"
say ""
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) say "Note: $BIN_DIR is not in your PATH. Add it, or use the full path above." ; say "" ;;
esac
if [ "$MODE" = "system" ]; then
  say "To run it as a service, read docs/SYSTEMD.md."
  say "This installer does not enable or start any service."
  say ""
fi
