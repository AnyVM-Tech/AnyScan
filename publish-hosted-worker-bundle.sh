#!/usr/bin/env bash
set -euo pipefail

HOSTED_DIR="${HOSTED_DIR:-/var/lib/anyscan/agent-bundles}"
BUNDLE_PATH="${1:-}"
SHA_PATH="${2:-}"

usage() {
    cat <<'EOF'
Usage:
  publish-hosted-worker-bundle.sh /path/to/agent-bundle-<platform>__<stamp>.tar.gz [/path/to/agent-bundle-<platform>__<stamp>.sha256]

Notes:
  - If the sha256 path is omitted, the script looks for a sibling .sha256 file.
  - Published files are copied into /var/lib/anyscan/agent-bundles by default.
EOF
}

if [ -z "$BUNDLE_PATH" ]; then
    usage >&2
    exit 1
fi

if [ -z "$SHA_PATH" ]; then
    SHA_PATH="${BUNDLE_PATH%.tar.gz}.sha256"
fi

if [ ! -f "$BUNDLE_PATH" ]; then
    printf '[!] Bundle file not found: %s\n' "$BUNDLE_PATH" >&2
    exit 1
fi

if [ ! -f "$SHA_PATH" ]; then
    printf '[!] Checksum file not found: %s\n' "$SHA_PATH" >&2
    exit 1
fi

BUNDLE_NAME="$(basename "$BUNDLE_PATH")"
SHA_NAME="$(basename "$SHA_PATH")"

case "$BUNDLE_NAME" in
    agent-bundle-*.tar.gz) ;;
    *)
        printf '[!] Bundle filename must start with agent-bundle- and end with .tar.gz\n' >&2
        exit 1
        ;;
esac

EXPECTED_SHA_NAME="${BUNDLE_NAME%.tar.gz}.sha256"
if [ "$SHA_NAME" != "$EXPECTED_SHA_NAME" ]; then
    printf '[!] Expected checksum filename %s but got %s\n' "$EXPECTED_SHA_NAME" "$SHA_NAME" >&2
    exit 1
fi

if ! grep -q "$BUNDLE_NAME" "$SHA_PATH"; then
    printf '[!] Checksum file %s does not reference %s\n' "$SHA_PATH" "$BUNDLE_NAME" >&2
    exit 1
fi

mkdir -p "$HOSTED_DIR"
install -m 0644 "$BUNDLE_PATH" "$HOSTED_DIR/$BUNDLE_NAME"
install -m 0644 "$SHA_PATH" "$HOSTED_DIR/$SHA_NAME"

printf '[*] Published hosted worker bundle:\n'
printf '    bundle: %s\n' "$HOSTED_DIR/$BUNDLE_NAME"
printf '    sha256: %s\n' "$HOSTED_DIR/$SHA_NAME"
