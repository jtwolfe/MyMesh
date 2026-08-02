#!/usr/bin/env bash
# MyMesh source install helper (v0.1.0-alpha.1)
# Builds the CLI from this repo. Does NOT install a systemd service yet.
# See docs/INSTALL-POLICY.md for the planned install model.
# MyMesh installer — builds from source on Linux and installs the mymesh binary.
set -euo pipefail

REPO_URL="${MYMESH_REPO_URL:-https://github.com/jtwolfe/MyMesh.git}"
BRANCH="${MYMESH_BRANCH:-main}"
INSTALL_DIR="${MYMESH_INSTALL_DIR:-$HOME/.local/bin}"
BUILD_DIR="${MYMESH_BUILD_DIR:-$(mktemp -d -t mymesh-build-XXXXXX)}"
CLEANUP=1

usage() {
  cat <<USAGE
MyMesh install script (Linux)

Usage: curl -fsSL https://raw.githubusercontent.com/jtwolfe/MyMesh/main/install.sh | bash

Environment:
  MYMESH_REPO_URL     Git clone URL (default: ${REPO_URL})
  MYMESH_BRANCH       Branch to build (default: ${BRANCH})
  MYMESH_INSTALL_DIR  Install prefix bin dir (default: ${INSTALL_DIR})
  MYMESH_BUILD_DIR    Working directory for the build
  MYMESH_NO_CLEANUP=1 Keep build directory
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${MYMESH_NO_CLEANUP:-0}" == "1" ]]; then
  CLEANUP=0
fi

cleanup() {
  if [[ "$CLEANUP" -eq 1 && -d "$BUILD_DIR" ]]; then
    rm -rf "$BUILD_DIR"
  fi
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

echo "==> MyMesh installer"
echo "    repo:    $REPO_URL"
echo "    branch:  $BRANCH"
echo "    install: $INSTALL_DIR"

need_cmd git
need_cmd cargo
need_cmd rustc

mkdir -p "$INSTALL_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Cloning..."
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR/src"

echo "==> Building (release)..."
(
  cd "$BUILD_DIR/src"
  cargo build --release -p mymesh-cli
)

BIN="$BUILD_DIR/src/target/release/mymesh"
if [[ ! -x "$BIN" ]]; then
  echo "error: build did not produce $BIN" >&2
  exit 1
fi

echo "==> Installing to $INSTALL_DIR/mymesh"
install -m 0755 "$BIN" "$INSTALL_DIR/mymesh"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo
    echo "Note: $INSTALL_DIR is not on your PATH."
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

echo
echo "Installed: $INSTALL_DIR/mymesh"
echo "Next:"
echo "  mymesh init"
echo "  mymesh status"
echo "  mymesh demo pair"
