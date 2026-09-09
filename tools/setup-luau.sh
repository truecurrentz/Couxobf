#!/usr/bin/env bash
# Build and install the pinned Luau toolchain.
#
# The differential tests execute both the original source and the protected
# output and compare behaviour, which needs a real Luau interpreter -- there is
# no way to fake that half of the verification.
#
# The version is pinned to a commit rather than "latest" so a test failure is
# attributable to the obfuscator and not to an upstream change.  Luau has no
# `--version` flag, so the commit hash in `TOOLCHAIN.md` is the only reliable
# record of what was used.
#
# Usage:
#   tools/setup-luau.sh                  # build into ./.luau-toolchain
#   COUXOBF_LUAU_DIR=/path tools/setup-luau.sh
#   tools/setup-luau.sh --rebuild        # ignore an existing install
#
# The install directory is gitignored; nothing here is vendored.

set -euo pipefail

LUAU_TAG="${LUAU_TAG:-0.700}"
LUAU_COMMIT="${LUAU_COMMIT:-3e1c94ec2c1a077497b7ac21f580745c7aeeefae}"
LUAU_REPO="${LUAU_REPO:-https://github.com/luau-lang/luau}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${COUXOBF_LUAU_DIR:-$REPO_ROOT/.luau-toolchain}"
SRC_DIR="${LUAU_SRC:-${TMPDIR:-/tmp}/luau-src-$LUAU_TAG}"
JOBS="${JOBS:-$( (nproc 2>/dev/null) || echo 2)}"

if [[ "${1:-}" == "--rebuild" ]]; then
  rm -rf "$INSTALL_DIR"
fi

BIN="$INSTALL_DIR/bin"
if [[ -x "$BIN/luau" && -x "$BIN/luau-compile" && -x "$BIN/luau-analyze" ]]; then
  echo "toolchain already present at $BIN"
  echo "set --rebuild to force a rebuild"
  exit 0
fi

# -- dependencies ----------------------------------------------------------

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake not found; installing via pip" >&2
  pip install --quiet --break-system-packages cmake ninja
fi

for tool in git make; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

if ! command -v g++ >/dev/null 2>&1 && ! command -v c++ >/dev/null 2>&1; then
  echo "no C++ compiler found (need g++ or c++)" >&2
  exit 1
fi

# -- source ----------------------------------------------------------------

if [[ ! -d "$SRC_DIR/.git" ]]; then
  echo "cloning $LUAU_REPO at tag $LUAU_TAG"
  rm -rf "$SRC_DIR"
  git clone --quiet --depth 1 --branch "$LUAU_TAG" "$LUAU_REPO" "$SRC_DIR"
fi

ACTUAL="$(git -C "$SRC_DIR" rev-parse HEAD)"
if [[ "$ACTUAL" != "$LUAU_COMMIT" ]]; then
  echo "WARNING: $SRC_DIR is at $ACTUAL, expected $LUAU_COMMIT" >&2
  echo "         pin mismatch; results may differ from CI" >&2
fi

# -- build -----------------------------------------------------------------

# Only the CLI targets.  `make` also builds the test suite and the type
# checker's SAT solver, which is most of the compile time and none of the use.
echo "building luau, luau-analyze, luau-compile with -j$JOBS"
make -C "$SRC_DIR" config=release luau luau-analyze luau-compile "-j$JOBS"

mkdir -p "$BIN"
for tool in luau luau-analyze luau-compile; do
  # the Makefile leaves symlinks in the source root; copy the real binaries so
  # the install survives the source tree being deleted
  cp -L "$SRC_DIR/build/release/$tool" "$BIN/$tool"
  chmod +x "$BIN/$tool"
done

echo
echo "installed to $BIN"
echo "add to your shell, or let find_toolchain() discover it:"
echo "  export COUXOBF_LUAU_DIR=$INSTALL_DIR"
