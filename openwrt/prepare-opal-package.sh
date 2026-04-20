#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$SCRIPT_DIR/package/anyscan-agent"
STAGE_ROOT="$PACKAGE_DIR/staging/root"

AGENT_BIN="${ANYSCAN_OPAL_AGENT_BIN:-}"
SCANNER_BIN="${ANYSCAN_OPAL_SCANNER_BIN:-}"

print_usage() {
    cat <<'EOF'
Usage:
  prepare-opal-package.sh --agent-bin /path/to/anyscan-worker --scanner-bin /path/to/scanner

Environment fallbacks:
  ANYSCAN_OPAL_AGENT_BIN
  ANYSCAN_OPAL_SCANNER_BIN

This script stages target-built binaries and helper assets into the OpenWrt
package skeleton so it can be copied into an OpenWrt/GL.iNet SDK tree.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --agent-bin)
            AGENT_BIN="${2:-}"
            shift 2
            ;;
        --scanner-bin)
            SCANNER_BIN="${2:-}"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            printf '[!] Unknown argument: %s\n' "$1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$AGENT_BIN" ] || [ ! -x "$AGENT_BIN" ]; then
    printf '[!] --agent-bin must point to an executable target-built worker binary.\n' >&2
    exit 1
fi

if [ -z "$SCANNER_BIN" ] || [ ! -x "$SCANNER_BIN" ]; then
    printf '[!] --scanner-bin must point to an executable target-built scanner binary.\n' >&2
    exit 1
fi

rm -rf "$STAGE_ROOT"
mkdir -p \
    "$STAGE_ROOT/usr/sbin" \
    "$STAGE_ROOT/usr/libexec/agentd" \
    "$STAGE_ROOT/usr/share/agentd/extensions" \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/manifests" \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/rules" \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/scripts"

install -m 0755 "$AGENT_BIN" "$STAGE_ROOT/usr/sbin/agentd"
install -m 0755 "$SCANNER_BIN" "$STAGE_ROOT/usr/libexec/agentd/scanner"

install -m 0644 "$SCRIPT_DIR/../local-bootstrap-provisioner.json" \
    "$STAGE_ROOT/usr/share/agentd/extensions/bootstrap-provisioner.json"
install -m 0755 "$SCRIPT_DIR/../local-bootstrap-provisioner.py" \
    "$STAGE_ROOT/usr/share/agentd/extensions/bootstrap-provisioner.py"
install -m 0644 "$SCRIPT_DIR/../vulnscanner-zmap-adapter.json" \
    "$STAGE_ROOT/usr/share/agentd/extensions/portscan-adapter.json"
install -m 0755 "$SCRIPT_DIR/../vulnscanner-zmap-adapter.py" \
    "$STAGE_ROOT/usr/share/agentd/extensions/portscan-adapter.py"

cp -R "$SCRIPT_DIR/../extensions/bundled/manifests/." \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/manifests/"
cp -R "$SCRIPT_DIR/../extensions/bundled/rules/." \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/rules/"
cp -R "$SCRIPT_DIR/../extensions/bundled/scripts/." \
    "$STAGE_ROOT/usr/share/agentd/extensions/bundled/scripts/"
chmod 0755 "$STAGE_ROOT"/usr/share/agentd/extensions/bundled/scripts/*.py

if command -v strip >/dev/null 2>&1; then
    strip --strip-all "$STAGE_ROOT/usr/sbin/agentd" 2>/dev/null || true
    strip --strip-all "$STAGE_ROOT/usr/libexec/agentd/scanner" 2>/dev/null || true
fi

printf '[*] OpenWrt package staging prepared at %s\n' "$STAGE_ROOT"
printf '[*] Next step: copy %s into your SDK as package/anyscan-agent and run make package/anyscan-agent/compile V=s\n' "$PACKAGE_DIR"
