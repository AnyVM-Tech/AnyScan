#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=""
OUTPUT_DIR="${ANYSCAN_OPAL_PUBLISH_DIR:-/var/lib/anyscan/openwrt-opal}"

usage() {
    cat <<'EOF'
Usage:
  publish-opal-packages.sh --source-dir /path/to/ipks [--output-dir /path/to/publish-dir]

Copies the built OpenWrt ipks into a flat publish directory with stable names.
Default output dir:
  /var/lib/anyscan/openwrt-opal

Files written:
  anyscan-agent-core.ipk
  anyscan-agent-helpers.ipk
  anyscan-agent-scanner.ipk
  anyscan-agent-opal-full.ipk
  install-opal-agent.sh
  SHA256SUMS

The stable names let the router-side installer download packages without
hardcoding SDK build version strings or target architecture suffixes.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-dir)
            SOURCE_DIR="${2:-}"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '[!] Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

[ -n "$SOURCE_DIR" ] || { printf '[!] --source-dir is required.\n' >&2; exit 1; }
[ -d "$SOURCE_DIR" ] || { printf '[!] Source directory not found: %s\n' "$SOURCE_DIR" >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"

copy_latest_match() {
    local pattern="$1"
    local dest_name="$2"
    local match

    match="$(find "$SOURCE_DIR" -maxdepth 1 -type f -name "$pattern" | sort | tail -n1)"
    [ -n "$match" ] || {
        printf '[!] No package matched %s in %s\n' "$pattern" "$SOURCE_DIR" >&2
        exit 1
    }

    install -m 0644 "$match" "$OUTPUT_DIR/$dest_name"
}

copy_latest_match 'anyscan-agent-core_*.ipk' 'anyscan-agent-core.ipk'
copy_latest_match 'anyscan-agent-helpers_*.ipk' 'anyscan-agent-helpers.ipk'
copy_latest_match 'anyscan-agent-scanner_*.ipk' 'anyscan-agent-scanner.ipk'
copy_latest_match 'anyscan-agent-opal-full_*.ipk' 'anyscan-agent-opal-full.ipk'

install -m 0755 "$SCRIPT_DIR/install-opal-agent.sh" "$OUTPUT_DIR/install-opal-agent.sh"

(
    cd "$OUTPUT_DIR"
    sha256sum \
        anyscan-agent-core.ipk \
        anyscan-agent-helpers.ipk \
        anyscan-agent-scanner.ipk \
        anyscan-agent-opal-full.ipk \
        install-opal-agent.sh > SHA256SUMS
)

printf '[*] Published OpenWrt agent packages to %s\n' "$OUTPUT_DIR"
