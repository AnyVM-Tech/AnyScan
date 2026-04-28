#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${DIST_DIR:-$SCRIPT_DIR/dist}"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
BUNDLE_PLATFORM_OVERRIDE="${ANYSCAN_PACKAGE_BUNDLE_PLATFORM:-}"
SCANNER_SOURCE_BIN="${ANYSCAN_PACKAGE_VULNSCANNER_BIN:-}"
AGENT_SOURCE_BIN="${ANYSCAN_PACKAGE_AGENT_BIN:-}"
TOR_SOURCE_BIN="${ANYSCAN_PACKAGE_TOR_BIN:-}"
TOR_SOURCE_GEOIP="${ANYSCAN_PACKAGE_TOR_GEOIP:-}"
TOR_SOURCE_GEOIP6="${ANYSCAN_PACKAGE_TOR_GEOIP6:-}"
CURRENT_RUNTIME_ENV="${ANYSCAN_PACKAGE_RUNTIME_ENV:-/etc/anyscan/runtime.env}"
API_BASE_URL_OVERRIDE="${ANYSCAN_PACKAGE_API_BASE_URL:-}"
BUNDLE_RUNTIME_API_BASE_URL_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_API_BASE_URL:-http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion}"
BUNDLE_RUNTIME_API_PROXY_URL_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_API_PROXY_URL:-socks5h://127.0.0.1:9050}"
BUNDLE_RUNTIME_MANAGEMENT_URL_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_MANAGEMENT_URL:-}"
BUNDLE_RUNTIME_REMOTE_UPDATE_INSTALLER_URL_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_REMOTE_UPDATE_INSTALLER_URL:-}"
TOKEN_LABEL_OVERRIDE="${ANYSCAN_PACKAGE_TOKEN_LABEL:-}"
TOKEN_EXPIRES_SECONDS="${ANYSCAN_PACKAGE_TOKEN_EXPIRES_SECONDS:-0}"
TOKEN_SINGLE_USE="${ANYSCAN_PACKAGE_TOKEN_SINGLE_USE:-true}"
TOKEN_ALLOW_RUNS_OVERRIDE="${ANYSCAN_PACKAGE_TOKEN_ALLOW_RUNS:-}"
TOKEN_ALLOW_PORT_SCANS_OVERRIDE="${ANYSCAN_PACKAGE_TOKEN_ALLOW_PORT_SCANS:-}"
TOKEN_ALLOW_BOOTSTRAP_OVERRIDE="${ANYSCAN_PACKAGE_TOKEN_ALLOW_BOOTSTRAP:-}"
WORKER_ID_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_ID:-}"
WORKER_NAME_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_NAME:-}"
WORKER_POOL_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_POOL:-}"
WORKER_TAGS_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_TAGS:-}"
WORKER_SUPPORTS_BOOTSTRAP_OVERRIDE="${ANYSCAN_PACKAGE_WORKER_SUPPORTS_BOOTSTRAP:-}"
BUNDLE_NAME_OVERRIDE="${ANYSCAN_PACKAGE_BUNDLE_NAME:-}"

# Build-time AF_XDP opt-in (mirrors install-external-deps.sh). When 1 and
# the staged scanner binary does not link libxdp, the bundle script
# rebuilds the engine with `make USE_AF_XDP=1` so the bundle ships an
# AF_XDP-capable scanner. Default 0 keeps existing bundle CI green.
# Source: plans/2026-04-27-portscan-afxdp-plan-v1.md §3.6 + anygpt-42.
ANYSCAN_USE_AF_XDP="${ANYSCAN_USE_AF_XDP:-0}"
# Build-time PF_RING ZC opt-in (anygpt-46). Same shape as ANYSCAN_USE_AF_XDP
# but probes for libpfring linkage and forwards USE_PFRING_ZC=1 to make.
# See install-external-deps.sh for license obligation notes (PF_RING ZC
# requires a commercial ntop license at runtime).
ANYSCAN_USE_PFRING_ZC="${ANYSCAN_USE_PFRING_ZC:-0}"
ANYSCAN_VULNSCANNER_REPO_DIR_DEFAULT="$SCRIPT_DIR/../../anyscan-engine-c"
ANYSCAN_VULNSCANNER_REPO_DIR="${ANYSCAN_VULNSCANNER_REPO_DIR:-$ANYSCAN_VULNSCANNER_REPO_DIR_DEFAULT}"

# Opt-in kernel backport flag (mirrors install-external-deps.sh /
# deploy.sh). Bundles do not contain a kernel image — the actual
# install happens at deploy time via install-external-deps.sh or
# deploy.sh on the target host. The bundle README records the flag
# so a downstream operator knows the producer's intent (e.g. "this
# bundle was built expecting kernel 6.16+ on the target"). Default
# 0; existing AMIs unchanged. See PR 65 issuecomment-4336192354 for
# the ENA / ena_xdp_zc constraint trace and anygpt-44 for this
# wire-up.
ANYSCAN_INSTALL_KERNEL_BACKPORT="${ANYSCAN_INSTALL_KERNEL_BACKPORT:-0}"

print_banner() {
    printf '═══════════════════════════════════════════════════════════\n'
    printf '                 Remote Agent Packager                   \n'
    printf '═══════════════════════════════════════════════════════════\n'
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

normalize_platform_os() {
    local value
    value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        macos) printf 'darwin\n' ;;
        *) printf '%s\n' "$value" ;;
    esac
}

normalize_platform_arch() {
    local value
    value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        amd64|x64) printf 'x86_64\n' ;;
        arm64) printf 'aarch64\n' ;;
        armv7l) printf 'armv7\n' ;;
        armv6l) printf 'armv6\n' ;;
        *) printf '%s\n' "$value" ;;
    esac
}

derive_bundle_platform() {
    local platform os arch
    platform="${BUNDLE_PLATFORM_OVERRIDE:-}"
    if [ -n "$platform" ]; then
        printf '%s\n' "$platform"
        return
    fi
    os="$(normalize_platform_os "$(uname -s)")"
    arch="$(normalize_platform_arch "$(uname -m)")"
    printf '%s-%s\n' "$os" "$arch"
}

copy_tree() {
    local source="$1"
    local dest="$2"
    mkdir -p "$dest"
    cp -R "$source"/. "$dest"/
}

env_value() {
    local key="$1"
    local file="$2"
    [ -f "$file" ] || return 1
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

derive_local_api_base_url() {
    local runtime_env="$1"
    if [ -n "$API_BASE_URL_OVERRIDE" ]; then
        printf '%s\n' "$API_BASE_URL_OVERRIDE"
        return
    fi

    local bind_addr host port
    bind_addr="$(env_value "ANYSCAN_BIND_ADDR" "$runtime_env" || true)"
    if [ -z "$bind_addr" ]; then
        printf 'http://127.0.0.1:8088\n'
        return
    fi

    host="${bind_addr%:*}"
    port="${bind_addr##*:}"
    case "$host" in
        ""|"0.0.0.0"|"::"|"[::]")
            host="127.0.0.1"
            ;;
    esac
    printf 'http://%s:%s\n' "$host" "$port"
}

json_string() {
    python3 - <<'PY' "$1"
import json, sys
print(json.dumps(sys.argv[1]))
PY
}

issue_worker_bootstrap_code() {
    local runtime_env="$1"
    local api_base_url="$2"
    local bootstrap_label="$3"
    local allow_runs="$4"
    local allow_port_scans="$5"
    local allow_bootstrap="$6"
    local expires_in_seconds="$7"
    local worker_id="$8"
    local worker_name="$9"
    local worker_pool="${10}"
    local worker_tags="${11}"

    local admin_username admin_password login_payload token_payload cookiejar login_body login_status token_body token_status
    admin_username="${ANYSCAN_PACKAGE_ADMIN_USERNAME:-$(env_value "ANYSCAN_ADMIN_USERNAME" "$runtime_env" || true)}"
    admin_password="${ANYSCAN_PACKAGE_ADMIN_PASSWORD:-$(env_value "ANYSCAN_ADMIN_PASSWORD" "$runtime_env" || true)}"

    if [ -z "$admin_username" ] || [ -z "$admin_password" ]; then
        printf '[!] Could not determine admin credentials for bootstrap-code issuance.\n' >&2
        exit 1
    fi

    cookiejar="$(mktemp)"
    login_payload="$(python3 - <<'PY' "$admin_username" "$admin_password"
import json, sys
print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
)"
    login_body="$(mktemp)"
    login_status="$(
        curl -sS \
            -o "$login_body" \
            -w '%{http_code}' \
            -c "$cookiejar" \
            -H 'content-type: application/json' \
            -d "$login_payload" \
            "$api_base_url/api/session"
    )"
    if [ "$login_status" != "200" ]; then
        printf '[!] Failed to authenticate to %s/api/session (status %s).\n' "$api_base_url" "$login_status" >&2
        cat "$login_body" >&2
        rm -f "$cookiejar" "$login_body"
        exit 1
    fi

    token_payload="$(python3 - <<'PY' "$bootstrap_label" "$allow_runs" "$allow_port_scans" "$allow_bootstrap" "$expires_in_seconds" "$worker_id" "$worker_name" "$worker_pool" "$worker_tags"
import json, sys
def as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
expires = int(sys.argv[5])
payload = {
    "label": sys.argv[1],
    "allow_runs": as_bool(sys.argv[2]),
    "allow_port_scans": as_bool(sys.argv[3]),
    "allow_bootstrap": as_bool(sys.argv[4]),
    "worker_id": sys.argv[6],
}
if sys.argv[7].strip():
    payload["worker_name"] = sys.argv[7]
if sys.argv[8].strip():
    payload["worker_pool"] = sys.argv[8]
if sys.argv[9].strip():
    payload["tags"] = [tag.strip() for tag in sys.argv[9].split(",") if tag.strip()]
if expires > 0:
    payload["expires_in_seconds"] = expires
print(json.dumps(payload))
PY
)"
    token_body="$(mktemp)"
    token_status="$(
        curl -sS \
            -o "$token_body" \
            -w '%{http_code}' \
            -b "$cookiejar" \
            -H 'content-type: application/json' \
            -d "$token_payload" \
            "$api_base_url/api/worker-bootstrap-codes"
    )"
    if [ "$token_status" != "200" ]; then
        printf '[!] Failed to issue worker bootstrap code (status %s).\n' "$token_status" >&2
        cat "$token_body" >&2
        rm -f "$cookiejar" "$login_body" "$token_body"
        exit 1
    fi

    python3 - <<'PY' "$token_body"
import json, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
print(payload["code"])
PY

    rm -f "$cookiejar" "$login_body" "$token_body"
}

write_bundled_runtime_env() {
    local dest_env="$1"
    local obfuscated_bootstrap_code="$2"
    local worker_supports_bootstrap="$3"
    local include_scanner="$4"
    local api_base_url="$5"
    local api_proxy_url="$6"
    local bundle_name="$7"
    local worker_id="$8"
    local worker_name="$9"
    local worker_pool="${10}"
    local worker_tags="${11}"
    local management_url="${12}"

    cat >"$dest_env" <<'EOF'
# Remote agent runtime bundle
# This file ships with an obfuscated one-time bootstrap code.
# The agent exchanges it for a persistent AGENT_TOKEN on first boot.
EOF

    cat >>"$dest_env" <<EOF
ALLOWED_HOST_SUFFIXES=
ALLOWED_HOSTS=
ALLOWED_CIDRS=
ALLOWED_PORTS=
POLL_INTERVAL_SECONDS=15
CONTROL_URL=${api_base_url}
AGENT_MANAGEMENT_URL=${management_url}
CONTROL_PROXY_URL=${api_proxy_url}
AGENT_BUNDLE_NAME=${bundle_name}
AGENT_ID=${worker_id}
AGENT_NAME=${worker_name}
AGENT_POOL=${worker_pool}
AGENT_TAGS=${worker_tags}
AGENT_STATE_FILE=/var/lib/agentd/agent.env
AGENT_BOOTSTRAP_CODE_OBFUSCATED=${obfuscated_bootstrap_code}
AGENT_BOOTSTRAP_CODE_OBFUSCATION=base64
AGENT_ENABLE_BOOTSTRAP=${worker_supports_bootstrap}
AGENT_REMOTE_UPDATE_ENABLED=true
AGENT_REMOTE_UPDATE_REQUEST_FILE=/var/lib/agentd/remote-update.request
AGENT_REMOTE_UPDATE_STATUS_FILE=/var/lib/agentd/remote-update.status
AGENT_REMOTE_UPDATE_BACKUP_ROOT=/var/lib/agentd/update-backups
AGENT_REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS=120
AGENT_REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS=5
AGENT_REMOTE_UPDATE_ROLLBACK_ON_FAILURE=true
AGENT_REMOTE_DEBUG_ENABLED=true
EXTENSION_MANIFEST_PATHS=/opt/agentd/extensions/bootstrap-provisioner.json,/opt/agentd/extensions/portscan-adapter.json
ARTIFACT_DIR=/var/lib/agentd/artifacts
EOF
    if [ -n "$BUNDLE_RUNTIME_REMOTE_UPDATE_INSTALLER_URL_OVERRIDE" ]; then
        printf 'AGENT_REMOTE_UPDATE_INSTALLER_URL=%s\n' \
            "$BUNDLE_RUNTIME_REMOTE_UPDATE_INSTALLER_URL_OVERRIDE" >>"$dest_env"
    fi
    if [ "$include_scanner" = "true" ]; then
        printf 'SCANNER_BIN=/opt/agentd/bin/scanner\n' >>"$dest_env"
    else
        printf '# SCANNER_BIN=/opt/agentd/bin/scanner\n' >>"$dest_env"
    fi
    cat >>"$dest_env" <<'EOF'
# Optional agent-local overrides
# AGENT_CONCURRENCY=16
# ALLOW_INVALID_TLS=false
# OUTBOUND_PROXY_MODE=direct_only
# OUTBOUND_PROXY_URL=
EOF
}

derive_bundle_runtime_api_base_url() {
    local api_base_url="$1"
    if [ -n "$BUNDLE_RUNTIME_API_BASE_URL_OVERRIDE" ]; then
        printf '%s\n' "$BUNDLE_RUNTIME_API_BASE_URL_OVERRIDE"
        return
    fi
    printf '%s\n' "$api_base_url"
}

derive_bundle_runtime_api_proxy_url() {
    printf '%s\n' "$BUNDLE_RUNTIME_API_PROXY_URL_OVERRIDE"
}

normalize_worker_identifier() {
    python3 - <<'PY' "$1"
import re, sys
value = sys.argv[1].strip().lower()
value = re.sub(r'[^a-z0-9._-]+', '-', value)
value = re.sub(r'-{2,}', '-', value).strip('-')
print(value)
PY
}

strip_binary() {
    local path="$1"
    if command_exists strip && [ -f "$path" ]; then
        strip --strip-all "$path" 2>/dev/null || true
    fi
}

# Mirror of binary_has_afxdp_linkage in install-external-deps.sh; kept
# inline rather than sourced so this script remains stand-alone for CI.
binary_has_afxdp_linkage() {
    local bin="$1"
    [ -x "$bin" ] || return 1
    if command_exists ldd; then
        if ldd "$bin" 2>/dev/null | grep -q 'libxdp\.so'; then
            return 0
        fi
    fi
    if command_exists readelf; then
        if readelf -d "$bin" 2>/dev/null | grep -E '\(NEEDED\)' | grep -q 'libxdp\.so'; then
            return 0
        fi
    fi
    return 1
}

# Mirror of binary_has_pfring_zc_linkage in install-external-deps.sh.
binary_has_pfring_zc_linkage() {
    local bin="$1"
    [ -x "$bin" ] || return 1
    if command_exists ldd; then
        if ldd "$bin" 2>/dev/null | grep -q 'libpfring\.so'; then
            return 0
        fi
    fi
    if command_exists readelf; then
        if readelf -d "$bin" 2>/dev/null | grep -E '\(NEEDED\)' | grep -q 'libpfring\.so'; then
            return 0
        fi
    fi
    return 1
}

# Resolve the engine make argv so cached invocations match
# install-external-deps.sh::vulnscanner_make_args byte-for-byte. Stays
# empty when both build flags are 0; otherwise emits one token per line.
bundle_engine_make_args() {
    if [ "${ANYSCAN_USE_AF_XDP:-0}" = "1" ]; then
        printf 'USE_AF_XDP=1\n'
    fi
    if [ "${ANYSCAN_USE_PFRING_ZC:-0}" = "1" ]; then
        printf 'USE_PFRING_ZC=1\n'
    fi
}

# Fire a `make USE_AF_XDP=1` in the engine repo so the bundle ships an
# AF_XDP-linked scanner. Used when ANYSCAN_USE_AF_XDP=1 and the cached
# binary either does not exist or was built without libxdp linkage.
# When ANYSCAN_USE_PFRING_ZC=1 is also set, the same invocation gets
# USE_PFRING_ZC=1 appended so a single make line links both code paths.
rebuild_scanner_with_afxdp() {
    local repo_dir="$1"
    if [ ! -f "$repo_dir/Makefile" ]; then
        printf '[!] ANYSCAN_USE_AF_XDP=1 requested but no Makefile at %s.\n' "$repo_dir" >&2
        printf '    Run install-external-deps.sh ANYSCAN_USE_AF_XDP=1 first, or set ANYSCAN_PACKAGE_VULNSCANNER_BIN to a pre-built AF_XDP-capable scanner binary.\n' >&2
        return 1
    fi
    if ! command_exists make; then
        printf '[!] make not on PATH; cannot rebuild scanner with USE_AF_XDP=1.\n' >&2
        return 1
    fi
    # shellcheck disable=SC2046  # word-splitting wanted: function emits 0+ tokens
    local make_args=( $(bundle_engine_make_args) )
    printf '[*] Rebuilding scanner in %s with %s...\n' "$repo_dir" "${make_args[*]}"
    make -C "$repo_dir" clean >/dev/null 2>&1 || true
    make -C "$repo_dir" "${make_args[@]}"
}

# Fire a `make USE_PFRING_ZC=1` (plus USE_AF_XDP=1 if also requested) so
# the bundle ships a libpfring-linked scanner. Mirrors
# rebuild_scanner_with_afxdp; the two helpers funnel through the same
# argv builder so both flags compose cleanly.
rebuild_scanner_with_pfring_zc() {
    local repo_dir="$1"
    if [ ! -f "$repo_dir/Makefile" ]; then
        printf '[!] ANYSCAN_USE_PFRING_ZC=1 requested but no Makefile at %s.\n' "$repo_dir" >&2
        printf '    Run install-external-deps.sh ANYSCAN_USE_PFRING_ZC=1 first, or set ANYSCAN_PACKAGE_VULNSCANNER_BIN to a pre-built PF_RING-ZC-capable scanner binary.\n' >&2
        return 1
    fi
    if ! command_exists make; then
        printf '[!] make not on PATH; cannot rebuild scanner with USE_PFRING_ZC=1.\n' >&2
        return 1
    fi
    # shellcheck disable=SC2046
    local make_args=( $(bundle_engine_make_args) )
    printf '[*] Rebuilding scanner in %s with %s...\n' "$repo_dir" "${make_args[*]}"
    make -C "$repo_dir" clean >/dev/null 2>&1 || true
    make -C "$repo_dir" "${make_args[@]}"
}

copy_runtime_file() {
    local source="$1"
    local dest_dir="$2"
    local mode="${3:-0644}"
    local resolved
    resolved="$(readlink -f "$source")"
    [ -f "$resolved" ] || return 1
    install -m "$mode" "$resolved" "$dest_dir/$(basename "$source")"
}

resolve_tor_runtime_sources() {
    local scratch_dir="$1"
    RESOLVED_TOR_BIN=""
    RESOLVED_TOR_GEOIP=""
    RESOLVED_TOR_GEOIP6=""
    RESOLVED_TOR_RUNTIME_ROOT=""

    if [ -n "$TOR_SOURCE_BIN" ]; then
        if [ ! -x "$TOR_SOURCE_BIN" ]; then
            printf '[!] ANYSCAN_PACKAGE_TOR_BIN=%s is not executable.\n' "$TOR_SOURCE_BIN" >&2
            exit 1
        fi
        RESOLVED_TOR_BIN="$TOR_SOURCE_BIN"
        if [ -n "$TOR_SOURCE_GEOIP" ] && [ -f "$TOR_SOURCE_GEOIP" ]; then
            RESOLVED_TOR_GEOIP="$TOR_SOURCE_GEOIP"
        elif [ -f /usr/share/tor/geoip ]; then
            RESOLVED_TOR_GEOIP="/usr/share/tor/geoip"
        fi
        if [ -n "$TOR_SOURCE_GEOIP6" ] && [ -f "$TOR_SOURCE_GEOIP6" ]; then
            RESOLVED_TOR_GEOIP6="$TOR_SOURCE_GEOIP6"
        elif [ -f /usr/share/tor/geoip6 ]; then
            RESOLVED_TOR_GEOIP6="/usr/share/tor/geoip6"
        fi
        return
    fi

    if command_exists tor; then
        RESOLVED_TOR_BIN="$(command -v tor)"
        [ -f /usr/share/tor/geoip ] && RESOLVED_TOR_GEOIP="/usr/share/tor/geoip"
        [ -f /usr/share/tor/geoip6 ] && RESOLVED_TOR_GEOIP6="/usr/share/tor/geoip6"
        return
    fi

    if command_exists apt && command_exists dpkg-deb; then
        local download_dir extract_dir dep_packages
        download_dir="$scratch_dir/tor-downloads"
        extract_dir="$scratch_dir/tor-extracted"
        mkdir -p "$download_dir" "$extract_dir"
        printf '[*] Downloading Tor packages for bundling...\n'
        mapfile -t dep_packages < <(apt-cache depends tor 2>/dev/null | awk '/Depends: / { print $2 }' | sort -u)
        (
            cd "$download_dir"
            apt download tor tor-geoipdb "${dep_packages[@]}" >/dev/null
        )
        local deb
        for deb in "$download_dir"/*.deb; do
            dpkg-deb -x "$deb" "$extract_dir"
        done
        RESOLVED_TOR_BIN="$extract_dir/usr/bin/tor"
        RESOLVED_TOR_GEOIP="$extract_dir/usr/share/tor/geoip"
        RESOLVED_TOR_GEOIP6="$extract_dir/usr/share/tor/geoip6"
        RESOLVED_TOR_RUNTIME_ROOT="$extract_dir"
        if [ ! -x "$RESOLVED_TOR_BIN" ]; then
            printf '[!] Failed to stage a Tor binary from downloaded packages.\n' >&2
            exit 1
        fi
        return
    fi

    printf '[!] Could not locate a Tor binary to bundle. Install tor locally or set ANYSCAN_PACKAGE_TOR_BIN.\n' >&2
    exit 1
}

resolve_tor_shared_library() {
    local library_name="$1"

    if [ -n "${RESOLVED_TOR_RUNTIME_ROOT:-}" ]; then
        local candidate
        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            printf '%s\n' "$candidate"
            return 0
        done < <(find \
            "$RESOLVED_TOR_RUNTIME_ROOT/lib" \
            "$RESOLVED_TOR_RUNTIME_ROOT/usr/lib" \
            \( -type f -o -type l \) -name "$library_name" 2>/dev/null | sort)
    fi

    if command_exists ldconfig; then
        local resolved
        resolved="$(
            ldconfig -p 2>/dev/null \
                | awk -v name="$library_name" '$1 == name { print $NF; exit }'
        )"
        if [ -n "$resolved" ] && [ -e "$resolved" ]; then
            printf '%s\n' "$resolved"
            return 0
        fi
    fi

    local fallback
    for fallback in \
        "/lib/$library_name" \
        "/lib64/$library_name" \
        "/usr/lib/$library_name" \
        "/lib/x86_64-linux-gnu/$library_name" \
        "/usr/lib/x86_64-linux-gnu/$library_name"
    do
        if [ -e "$fallback" ]; then
            printf '%s\n' "$fallback"
            return 0
        fi
    done

    return 1
}

stage_tor_runtime() {
    local dest_root="$1"
    local scratch_dir="$2"
    mkdir -p "$dest_root/bin" "$dest_root/lib" "$dest_root/share"
    resolve_tor_runtime_sources "$scratch_dir"

    printf '[*] Staging bundled Tor runtime from %s...\n' "$RESOLVED_TOR_BIN"
    install -m 0755 "$RESOLVED_TOR_BIN" "$dest_root/bin/tor.real"
    strip_binary "$dest_root/bin/tor.real"

    if [ -f "$RESOLVED_TOR_GEOIP" ]; then
        install -m 0644 "$RESOLVED_TOR_GEOIP" "$dest_root/share/geoip"
    fi
    if [ -f "$RESOLVED_TOR_GEOIP6" ]; then
        install -m 0644 "$RESOLVED_TOR_GEOIP6" "$dest_root/share/geoip6"
    fi

    local interpreter
    interpreter="$(
        readelf -l "$RESOLVED_TOR_BIN" 2>/dev/null \
            | awk '/Requesting program interpreter/ { gsub(/[\[\]]/, "", $NF); print $NF; exit }'
    )"
    if [ -n "$interpreter" ] && [ -e "$interpreter" ]; then
        copy_runtime_file "$interpreter" "$dest_root/lib" 0755
    fi

    local library_name library_path
    while IFS= read -r library_name; do
        [ -n "$library_name" ] || continue
        library_path="$(resolve_tor_shared_library "$library_name" || true)"
        if [ -z "$library_path" ]; then
            printf '[!] Failed to resolve Tor shared library %s for bundling.\n' "$library_name" >&2
            exit 1
        fi
        copy_runtime_file "$library_path" "$dest_root/lib" 0644
    done < <(readelf -d "$RESOLVED_TOR_BIN" 2>/dev/null | awk -F'[][]' '/NEEDED/ { print $2 }' | sort -u)
}

main() {
    print_banner

    local os arch platform bundle_name bundle_root stage_root cargo_target_dir worker_binary bundle_path checksum_path bundle_env_file api_base_url runtime_api_base_url runtime_api_proxy_url bootstrap_label worker_supports_bootstrap allow_runs allow_port_scans allow_bootstrap bootstrap_code include_scanner obfuscated_bootstrap_code worker_id_suffix worker_id worker_name worker_pool worker_tags build_rustflags
    platform="$(derive_bundle_platform)"
    os="$(normalize_platform_os "${platform%%-*}")"
    arch="$(normalize_platform_arch "${platform#*-}")"
    bundle_name="${BUNDLE_NAME_OVERRIDE:-agent-bundle-${platform}__$(date -u +%Y%m%d%H%M%S)-$$}"
    stage_root="$(mktemp -d)"
    bundle_root="$stage_root/$bundle_name"

    mkdir -p "$DIST_DIR"
    mkdir -p "$bundle_root/bin" "$bundle_root/extensions" "$bundle_root/extensions/bundled/manifests" "$bundle_root/extensions/bundled/rules" "$bundle_root/extensions/bundled/scripts" "$bundle_root/env" "$bundle_root/tor/bin" "$bundle_root/tor/lib" "$bundle_root/tor/share"

    if [ -n "$AGENT_SOURCE_BIN" ]; then
        printf '[*] Using prebuilt agent runtime from %s...\n' "$AGENT_SOURCE_BIN"
        worker_binary="$AGENT_SOURCE_BIN"
    else
        printf '[*] Building release agent runtime...\n'
        build_rustflags="${RUSTFLAGS:-}"
        if [ -n "$build_rustflags" ]; then
            build_rustflags="$build_rustflags "
        fi
        build_rustflags="${build_rustflags}--remap-path-prefix=$SCRIPT_DIR/src/bin/anyscan-worker.rs=src/bin/agentd.rs --remap-path-prefix=$SCRIPT_DIR=."
        if [ -n "$TARGET_TRIPLE" ]; then
            env RUSTFLAGS="$build_rustflags" CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=0 cargo build \
                --manifest-path "$SCRIPT_DIR/Cargo.toml" \
                --release \
                --locked \
                --features worker-bundle-stealth \
                --bin anyscan-worker \
                --target "$TARGET_TRIPLE"
            cargo_target_dir="$SCRIPT_DIR/target/$TARGET_TRIPLE/release"
        else
            env RUSTFLAGS="$build_rustflags" CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=0 cargo build \
                --manifest-path "$SCRIPT_DIR/Cargo.toml" \
                --release \
                --locked \
                --features worker-bundle-stealth \
                --bin anyscan-worker
            cargo_target_dir="$SCRIPT_DIR/target/release"
        fi

        worker_binary="$cargo_target_dir/anyscan-worker"
    fi
    if [ ! -x "$worker_binary" ]; then
        printf '[!] Failed to find agent runtime binary at %s\n' "$worker_binary" >&2
        exit 1
    fi
    install -m 0755 "$worker_binary" "$bundle_root/bin/agentd"
    strip_binary "$bundle_root/bin/agentd"

    if [ -z "$SCANNER_SOURCE_BIN" ]; then
        # Prefer the AnyVM-Tech fork of the scanner C source (anyscan-engine-c)
        # which carries the AF_XDP integration patches; fall back to the legacy
        # upstream-clone path and the system-installed binary.
        # See plans/2026-04-27-portscan-afxdp-plan-v1.md §9.1.
        if [ -x "$ANYSCAN_VULNSCANNER_REPO_DIR/scanner" ]; then
            SCANNER_SOURCE_BIN="$ANYSCAN_VULNSCANNER_REPO_DIR/scanner"
        elif [ -x "$SCRIPT_DIR/../../VulnScanner-zmap-alternative-/scanner" ]; then
            SCANNER_SOURCE_BIN="$SCRIPT_DIR/../../VulnScanner-zmap-alternative-/scanner"
        elif [ -x /opt/anyscan/bin/scanner ]; then
            SCANNER_SOURCE_BIN="/opt/anyscan/bin/scanner"
        fi
    fi
    # AF_XDP wire-up (anygpt-42 / plans/2026-04-27-portscan-afxdp-plan-v1.md
    # §3.6): when the operator opts in via ANYSCAN_USE_AF_XDP=1 and the
    # candidate binary either does not exist or is the legacy AF_PACKET-only
    # build, fire `make USE_AF_XDP=1` in the engine repo so the bundle
    # actually ships an AF_XDP-capable scanner. Without this step the
    # runtime --io-engine=af_xdp flag has no AF_XDP code to dispatch to,
    # which is the gap anygpt-42 caught.
    if [ "${ANYSCAN_USE_AF_XDP:-0}" = "1" ]; then
        local needs_engine_rebuild=0
        if [ -z "$SCANNER_SOURCE_BIN" ] || [ ! -x "$SCANNER_SOURCE_BIN" ]; then
            needs_engine_rebuild=1
        elif ! binary_has_afxdp_linkage "$SCANNER_SOURCE_BIN"; then
            printf '[*] %s lacks libxdp linkage; ANYSCAN_USE_AF_XDP=1 requires a rebuild.\n' "$SCANNER_SOURCE_BIN"
            needs_engine_rebuild=1
        fi
        if [ "$needs_engine_rebuild" = "1" ]; then
            if ! rebuild_scanner_with_afxdp "$ANYSCAN_VULNSCANNER_REPO_DIR"; then
                printf '[!] ANYSCAN_USE_AF_XDP=1 but unable to produce an AF_XDP-linked scanner. Aborting bundle.\n' >&2
                exit 1
            fi
            SCANNER_SOURCE_BIN="$ANYSCAN_VULNSCANNER_REPO_DIR/scanner"
        fi
        if [ ! -x "$SCANNER_SOURCE_BIN" ] || ! binary_has_afxdp_linkage "$SCANNER_SOURCE_BIN"; then
            printf '[!] Scanner at %s still lacks libxdp linkage after rebuild. Aborting bundle.\n' \
                "$SCANNER_SOURCE_BIN" >&2
            exit 1
        fi
    fi
    # PF_RING ZC wire-up (anygpt-46): same shape as AF_XDP. When
    # ANYSCAN_USE_PFRING_ZC=1 and the candidate binary lacks libpfring
    # linkage, fire `make USE_PFRING_ZC=1` so the bundled scanner has
    # the PF_RING ZC io_engine vtable wired in. Composes with AF_XDP —
    # if both flags are 1 the AF_XDP block above already produced a
    # binary linked with both libxdp and libpfring (bundle_engine_make_args
    # emits both tokens) so this branch becomes a no-op linkage check.
    if [ "${ANYSCAN_USE_PFRING_ZC:-0}" = "1" ]; then
        local needs_pfring_rebuild=0
        if [ -z "$SCANNER_SOURCE_BIN" ] || [ ! -x "$SCANNER_SOURCE_BIN" ]; then
            needs_pfring_rebuild=1
        elif ! binary_has_pfring_zc_linkage "$SCANNER_SOURCE_BIN"; then
            printf '[*] %s lacks libpfring linkage; ANYSCAN_USE_PFRING_ZC=1 requires a rebuild.\n' "$SCANNER_SOURCE_BIN"
            needs_pfring_rebuild=1
        fi
        if [ "$needs_pfring_rebuild" = "1" ]; then
            if ! rebuild_scanner_with_pfring_zc "$ANYSCAN_VULNSCANNER_REPO_DIR"; then
                printf '[!] ANYSCAN_USE_PFRING_ZC=1 but unable to produce a libpfring-linked scanner. Aborting bundle.\n' >&2
                exit 1
            fi
            SCANNER_SOURCE_BIN="$ANYSCAN_VULNSCANNER_REPO_DIR/scanner"
        fi
        if [ ! -x "$SCANNER_SOURCE_BIN" ] || ! binary_has_pfring_zc_linkage "$SCANNER_SOURCE_BIN"; then
            printf '[!] Scanner at %s still lacks libpfring linkage after rebuild. Aborting bundle.\n' \
                "$SCANNER_SOURCE_BIN" >&2
            exit 1
        fi
    fi
    include_scanner="false"
    if [ -n "$SCANNER_SOURCE_BIN" ] && [ -x "$SCANNER_SOURCE_BIN" ]; then
        printf '[*] Including scanner binary from %s...\n' "$SCANNER_SOURCE_BIN"
        install -m 0755 "$SCANNER_SOURCE_BIN" "$bundle_root/bin/scanner"
        strip_binary "$bundle_root/bin/scanner"
        include_scanner="true"
    else
        printf '[*] No scanner binary found to bundle. Port-scan support will need to be added on the target host.\n'
    fi

    stage_tor_runtime "$bundle_root/tor" "$stage_root"

    printf '[*] Staging extension assets...\n'
    install -m 0644 "$SCRIPT_DIR/local-bootstrap-provisioner.json" "$bundle_root/extensions/bootstrap-provisioner.json"
    install -m 0755 "$SCRIPT_DIR/local-bootstrap-provisioner.py" "$bundle_root/extensions/bootstrap-provisioner.py"
    install -m 0644 "$SCRIPT_DIR/vulnscanner-zmap-adapter.json" "$bundle_root/extensions/portscan-adapter.json"
    install -m 0755 "$SCRIPT_DIR/vulnscanner-zmap-adapter.py" "$bundle_root/extensions/portscan-adapter.py"
    install -m 0644 "$SCRIPT_DIR/anyscan_rate_controller.py" "$bundle_root/extensions/anyscan_rate_controller.py"
    copy_tree "$SCRIPT_DIR/extensions/bundled/manifests" "$bundle_root/extensions/bundled/manifests"
    copy_tree "$SCRIPT_DIR/extensions/bundled/rules" "$bundle_root/extensions/bundled/rules"
    copy_tree "$SCRIPT_DIR/extensions/bundled/scripts" "$bundle_root/extensions/bundled/scripts"
    chmod 0755 "$bundle_root/extensions"/bundled/scripts/*.py

    printf '[*] Staging installer and runtime env files...\n'
    install -m 0755 "$SCRIPT_DIR/bootstrap-agent-host.sh" "$bundle_root/bootstrap-agent-host.sh"
    install -m 0755 "$SCRIPT_DIR/install-worker-bundle.sh" "$bundle_root/install-worker-bundle.sh"
    install -m 0755 "$SCRIPT_DIR/reserve-control-bandwidth.sh" "$bundle_root/bin/reserve-control-bandwidth.sh"
    install -m 0755 "$SCRIPT_DIR/tools/tune-scanner-host.sh" "$bundle_root/bin/tune-scanner-host.sh"
    install -m 0644 "$SCRIPT_DIR/runtime.worker.env.template" "$bundle_root/env/runtime.env.template"

    worker_supports_bootstrap="$WORKER_SUPPORTS_BOOTSTRAP_OVERRIDE"
    if [ -z "$worker_supports_bootstrap" ]; then
        worker_supports_bootstrap="$(env_value "ANYSCAN_WORKER_SUPPORTS_BOOTSTRAP" "$CURRENT_RUNTIME_ENV" || true)"
    fi
    if [ -z "$worker_supports_bootstrap" ]; then
        worker_supports_bootstrap="false"
    fi

    api_base_url="$(derive_local_api_base_url "$CURRENT_RUNTIME_ENV")"
    runtime_api_base_url="$(derive_bundle_runtime_api_base_url "$api_base_url")"
    runtime_api_proxy_url="$(derive_bundle_runtime_api_proxy_url)"
    local runtime_management_url
    runtime_management_url="${BUNDLE_RUNTIME_MANAGEMENT_URL_OVERRIDE:-$runtime_api_base_url}"
    bootstrap_label="${TOKEN_LABEL_OVERRIDE:-${bundle_name}-$(date -u +%Y%m%d%H%M%S)}"
    allow_runs="${TOKEN_ALLOW_RUNS_OVERRIDE:-true}"
    allow_port_scans="${TOKEN_ALLOW_PORT_SCANS_OVERRIDE:-$include_scanner}"
    allow_bootstrap="${TOKEN_ALLOW_BOOTSTRAP_OVERRIDE:-$worker_supports_bootstrap}"
    worker_id_suffix="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
    worker_id="${WORKER_ID_OVERRIDE:-agent-${worker_id_suffix}}"
    worker_id="$(normalize_worker_identifier "$worker_id")"
    worker_name="${WORKER_NAME_OVERRIDE:-$worker_id}"
    worker_pool="${WORKER_POOL_OVERRIDE:-}"
    worker_tags="${WORKER_TAGS_OVERRIDE:-}"

    printf '[*] Issuing one-time worker bootstrap code from %s...\n' "$api_base_url"
    bootstrap_code="$(issue_worker_bootstrap_code \
        "$CURRENT_RUNTIME_ENV" \
        "$api_base_url" \
        "$bootstrap_label" \
        "$allow_runs" \
        "$allow_port_scans" \
        "$allow_bootstrap" \
        "$TOKEN_EXPIRES_SECONDS" \
        "$worker_id" \
        "$worker_name" \
        "$worker_pool" \
        "$worker_tags")"
    obfuscated_bootstrap_code="$(printf '%s' "$bootstrap_code" | base64 | tr -d '\n')"

    bundle_env_file="$bundle_root/env/runtime.env"
    write_bundled_runtime_env \
        "$bundle_env_file" \
        "$obfuscated_bootstrap_code" \
        "$worker_supports_bootstrap" \
        "$include_scanner" \
        "$runtime_api_base_url" \
        "$runtime_api_proxy_url" \
        "$bundle_name" \
        "$worker_id" \
        "$worker_name" \
        "$worker_pool" \
        "$worker_tags" \
        "$runtime_management_url"

    mkdir -p "$bundle_root/systemd"
    install -m 0644 "$SCRIPT_DIR/anyscan-worker-only.service" "$bundle_root/systemd/agentd.service"
    install -m 0644 "$SCRIPT_DIR/anyscan-worker-tor.service" "$bundle_root/systemd/agentd-tunnel.service"
    install -m 0644 "$SCRIPT_DIR/anyscan-worker-remote-update.service" "$bundle_root/systemd/agentd-remote-update.service"
    install -m 0644 "$SCRIPT_DIR/anyscan-worker-remote-update.path" "$bundle_root/systemd/agentd-remote-update.path"
    install -m 0755 "$SCRIPT_DIR/agentd-remote-update.sh" "$bundle_root/bin/agentd-remote-update.sh"

    printf '[*] Writing bundle README...\n'
    cat >"$bundle_root/README.txt" <<EOF
Remote agent bundle for ${os}/${arch}

Contents:
  - bin/agentd
  - bin/reserve-control-bandwidth.sh
  - bin/tune-scanner-host.sh
  - optional bin/scanner
  - tor/ (bundled tor binary, libs, geoip data)
  - extensions/
  - systemd/agentd.service
  - systemd/agentd-tunnel.service
  - systemd/agentd-remote-update.service
  - systemd/agentd-remote-update.path
  - env/runtime.env (with obfuscated one-time bootstrap code)
  - env/runtime.env.template
  - bootstrap-agent-host.sh
  - install-worker-bundle.sh

Install on the target host:
  tar -xzf ${bundle_name}.tar.gz
  cd ${bundle_name}
  sudo ./bootstrap-agent-host.sh

After install:
  1. The installer will install and enable the bundled Tor sidecar service for onion connectivity
  2. It runs the bundled installer, enables agentd, and waits for bootstrap/token persistence
  3. Edit /etc/agentd/runtime.env only if you want to override the preset control URL, agent id, pool, or tags

Bundle bootstrap details:
  label: ${bootstrap_label}
  obfuscation: base64
  single_use: true
  allow_runs: ${allow_runs}
  allow_port_scans: ${allow_port_scans}
  allow_bootstrap: ${allow_bootstrap}
  expires_in_seconds: ${TOKEN_EXPIRES_SECONDS}
Bundle agent identity:
  agent_id: ${worker_id}
  agent_name: ${worker_name}
  agent_pool: ${worker_pool:-<unset>}
  agent_tags: ${worker_tags:-<unset>}
Bundle control route:
  control_url: ${runtime_api_base_url}
  management_url: ${runtime_management_url}
  control_proxy_url: ${runtime_api_proxy_url}
Bundle scanner build:
  scanner_included: ${include_scanner}
  use_af_xdp: ${ANYSCAN_USE_AF_XDP}
  use_pfring_zc: ${ANYSCAN_USE_PFRING_ZC}
  install_kernel_backport: ${ANYSCAN_INSTALL_KERNEL_BACKPORT}
EOF

    bundle_path="$DIST_DIR/${bundle_name}.tar.gz"
    checksum_path="$DIST_DIR/${bundle_name}.sha256"
    printf '[*] Creating bundle %s...\n' "$bundle_path"
    tar -C "$stage_root" -czf "$bundle_path" "$bundle_name"
    (
        cd "$DIST_DIR"
        sha256sum "$bundle_name.tar.gz" >"$bundle_name.sha256"
    )

    rm -rf "$stage_root"

    printf '\nBundle ready.\n\n'
    printf '  bundle:   %s\n' "$bundle_path"
    printf '  sha256:   %s\n' "$checksum_path"
    printf '\nTransfer both files to the new host, extract the tarball, and run:\n'
    printf '  sudo ./bootstrap-agent-host.sh\n'
}

main "$@"
