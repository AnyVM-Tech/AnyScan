#!/bin/sh
set -eu

PROFILE="full"
BASE_URL="${ANYSCAN_OPAL_BASE_URL:-}"
BOOTSTRAP_CODE=""
CONTROL_URL="http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion"
CONTROL_PROXY_URL="socks5h://127.0.0.1:9050"
ENABLE="1"
TOR_WAIT_TIMEOUT="120"
AGENT_ID=""
AGENT_NAME=""
AGENT_POOL=""
AGENT_TAGS="router,opal"

usage() {
    cat <<'EOF'
Usage:
  install-opal-agent.sh --base-url https://host/path --bootstrap-code CODE [options]

Required:
  --base-url URL           Base URL containing published ipks and SHA256SUMS
  --bootstrap-code CODE    One-time bootstrap code for the router worker

Options:
  --profile core|helpers|scanner|full   Package profile to install (default: full)
  --control-url URL                     Control API URL (default: current onion URL)
  --control-proxy-url URL               Proxy URL for onion access (default: socks5h://127.0.0.1:9050)
  --agent-id VALUE                      Explicit agent ID (default: hostname)
  --agent-name VALUE                    Explicit agent name (default: agent ID)
  --agent-pool VALUE                    Optional worker pool
  --agent-tags CSV                      Comma-separated tags (default: router,opal)
  --disable                             Install and configure, but do not enable/start agentd
  --tor-wait-timeout SECONDS            Wait time for local Tor SOCKS readiness (default: 120)
  -h, --help                            Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --base-url)
            BASE_URL="${2:-}"
            shift 2
            ;;
        --bootstrap-code)
            BOOTSTRAP_CODE="${2:-}"
            shift 2
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --control-url)
            CONTROL_URL="${2:-}"
            shift 2
            ;;
        --control-proxy-url)
            CONTROL_PROXY_URL="${2:-}"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="${2:-}"
            shift 2
            ;;
        --agent-name)
            AGENT_NAME="${2:-}"
            shift 2
            ;;
        --agent-pool)
            AGENT_POOL="${2:-}"
            shift 2
            ;;
        --agent-tags)
            AGENT_TAGS="${2:-}"
            shift 2
            ;;
        --tor-wait-timeout)
            TOR_WAIT_TIMEOUT="${2:-}"
            shift 2
            ;;
        --disable)
            ENABLE="0"
            shift
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

[ -n "$BASE_URL" ] || { printf '[!] --base-url is required.\n' >&2; exit 1; }
[ -n "$BOOTSTRAP_CODE" ] || { printf '[!] --bootstrap-code is required.\n' >&2; exit 1; }

case "$PROFILE" in
    core|helpers|scanner|full) ;;
    *)
        printf '[!] Invalid profile: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

if [ -z "$AGENT_ID" ]; then
    AGENT_ID="$(cat /proc/sys/kernel/hostname 2>/dev/null || echo opal-agent)"
fi
if [ -z "$AGENT_NAME" ]; then
    AGENT_NAME="$AGENT_ID"
fi

BASE_URL="${BASE_URL%/}"
TMPDIR="$(mktemp -d /tmp/anyscan-opal-install.XXXXXX)"
cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fetch() {
    local url="$1"
    local dest="$2"

    if command -v uclient-fetch >/dev/null 2>&1; then
        uclient-fetch -O "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$dest" "$url"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    else
        printf '[!] Need one of: uclient-fetch, wget, curl\n' >&2
        exit 1
    fi
}

verify_checksum() {
    local file="$1"
    local sums_file="$2"
    local expected actual base

    base="$(basename "$file")"
    expected="$(awk -v name="$base" '$2 == name { print $1; exit }' "$sums_file")"
    [ -n "$expected" ] || {
        printf '[!] Missing checksum entry for %s\n' "$base" >&2
        exit 1
    }
    actual="$(sha256sum "$file" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || {
        printf '[!] Checksum mismatch for %s\n' "$base" >&2
        exit 1
    }
}

printf '[*] Updating package indexes...\n'
opkg update

printf '[*] Installing feed dependencies...\n'
case "$PROFILE" in
    core)
        opkg install ca-bundle
        ;;
    helpers)
        opkg install ca-bundle python3-light
        ;;
    scanner)
        opkg install ca-bundle
        ;;
    full)
        opkg install ca-bundle tor python3-light
        ;;
esac

printf '[*] Downloading package checksums...\n'
fetch "$BASE_URL/SHA256SUMS" "$TMPDIR/SHA256SUMS"

PACKAGE_FILES=""
download_package() {
    local name="$1"
    local dest="$TMPDIR/$name"
    printf '[*] Downloading %s...\n' "$name"
    fetch "$BASE_URL/$name" "$dest"
    verify_checksum "$dest" "$TMPDIR/SHA256SUMS"
    PACKAGE_FILES="$PACKAGE_FILES $dest"
}

download_package anyscan-agent-core.ipk

case "$PROFILE" in
    helpers|full)
        download_package anyscan-agent-helpers.ipk
        ;;
esac

case "$PROFILE" in
    scanner|full)
        download_package anyscan-agent-scanner.ipk
        ;;
esac

if [ "$PROFILE" = "full" ]; then
    download_package anyscan-agent-opal-full.ipk
fi

printf '[*] Installing local ipks...\n'
# shellcheck disable=SC2086
opkg install $PACKAGE_FILES

printf '[*] Writing UCI config...\n'
uci set agentd.main.enabled="$ENABLE"
uci set agentd.main.control_url="$CONTROL_URL"
uci set agentd.main.control_proxy_url="$CONTROL_PROXY_URL"
uci set agentd.main.agent_id="$AGENT_ID"
uci set agentd.main.agent_name="$AGENT_NAME"
uci set agentd.main.agent_pool="$AGENT_POOL"
uci set agentd.main.bootstrap_code="$BOOTSTRAP_CODE"
uci set agentd.main.tor_wait_timeout="$TOR_WAIT_TIMEOUT"

case "$PROFILE" in
    core)
        uci set agentd.main.enable_bootstrap='0'
        uci set agentd.main.enable_scanner='0'
        ;;
    helpers)
        uci set agentd.main.enable_bootstrap='1'
        uci set agentd.main.enable_scanner='0'
        ;;
    scanner)
        uci set agentd.main.enable_bootstrap='0'
        uci set agentd.main.enable_scanner='1'
        ;;
    full)
        uci set agentd.main.enable_bootstrap='1'
        uci set agentd.main.enable_scanner='1'
        ;;
esac

uci -q delete agentd.main.agent_tag || true
OLD_IFS="$IFS"
IFS=','
set -- $AGENT_TAGS
IFS="$OLD_IFS"
for tag in "$@"; do
    [ -n "$tag" ] || continue
    uci add_list agentd.main.agent_tag="$tag"
done

uci commit agentd

if [ "$PROFILE" = "full" ] || [ "$CONTROL_URL" != "${CONTROL_URL#*.onion}" ]; then
    if [ -x /etc/init.d/tor ]; then
        printf '[*] Enabling and starting tor...\n'
        /etc/init.d/tor enable || true
        /etc/init.d/tor restart || /etc/init.d/tor start || true
    fi
fi

if [ -x /etc/init.d/agentd ]; then
    if [ "$ENABLE" = "1" ]; then
        printf '[*] Enabling and starting agentd...\n'
        /etc/init.d/agentd enable
        /etc/init.d/agentd restart || /etc/init.d/agentd start
    else
        printf '[*] agentd installed but left disabled.\n'
    fi
fi

printf '\nInstall complete.\n'
printf 'Control URL: %s\n' "$CONTROL_URL"
printf 'Profile: %s\n' "$PROFILE"
printf 'Agent ID: %s\n' "$AGENT_ID"
