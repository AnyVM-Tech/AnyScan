#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ENV_FILE="${RUNTIME_ENV_FILE:-/etc/agentd/runtime.env}"
DEFAULT_REQUEST_FILE="/var/lib/agentd/remote-update.request"
DEFAULT_STATUS_FILE="/var/lib/agentd/remote-update.status"
DEFAULT_STATE_FILE="/var/lib/agentd/agent.env"
DEFAULT_BACKUP_ROOT="/var/lib/agentd/update-backups"
DEFAULT_AGENT_SERVICE_NAME="agentd.service"
DEFAULT_TOR_SERVICE_NAME="agentd-tunnel.service"
DEFAULT_UPDATE_PATH_UNIT_NAME="agentd-remote-update.path"
DEFAULT_INSTALL_ROOT="/opt/agentd"
DEFAULT_CONFIG_DIR="/etc/agentd"
DEFAULT_SYSTEMD_DIR="/etc/systemd/system"
BACKUP_KEEP_COUNT="${AGENT_REMOTE_UPDATE_BACKUP_KEEP_COUNT:-5}"

TMP_SCRIPT=""
TMP_REQUEST=""
ROLLBACK_BACKUP_DIR=""

cleanup() {
    [ -n "$TMP_SCRIPT" ] && rm -f "$TMP_SCRIPT"
    [ -n "$TMP_REQUEST" ] && rm -f "$TMP_REQUEST"
}
trap cleanup EXIT

read_env_value() {
    local key="$1"
    local file="$2"
    [ -f "$file" ] || return 1
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

encode_query_value() {
    python3 - <<'PY' "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

write_status() {
    local status="$1"
    local message="$2"
    local status_file="$3"
    umask 022
    cat >"$status_file" <<EOF
STATUS=$status
UPDATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
MESSAGE=$message
EOF
}

log_info() {
    printf '[*] %s\n' "$1"
}

log_warn() {
    printf '[!] %s\n' "$1" >&2
}

runtime_env_requires_tor() {
    local api_base_url api_proxy_url
    api_base_url="$(read_env_value "CONTROL_URL" "$RUNTIME_ENV_FILE" || true)"
    api_proxy_url="$(read_env_value "CONTROL_PROXY_URL" "$RUNTIME_ENV_FILE" || true)"
    case "$api_base_url" in
        *".onion"*|*".onion/"*)
            return 0
            ;;
    esac
    case "$api_proxy_url" in
        socks5h://*|socks5://*)
            return 0
            ;;
    esac
    return 1
}

derive_installer_url() {
    local explicit_url management_url encoded_base_url
    explicit_url="${AGENT_REMOTE_UPDATE_INSTALLER_URL:-}"
    if [ -n "$explicit_url" ]; then
        printf '%s\n' "$explicit_url"
        return
    fi

    management_url="${AGENT_MANAGEMENT_URL:-}"
    if [ -z "$management_url" ]; then
        management_url="$(read_env_value "AGENT_MANAGEMENT_URL" "$RUNTIME_ENV_FILE" || true)"
    fi
    if [ -z "$management_url" ]; then
        management_url="$(read_env_value "CONTROL_URL" "$RUNTIME_ENV_FILE" || true)"
    fi
    [ -n "$management_url" ] || return 1

    encoded_base_url="$(encode_query_value "$management_url")"
    printf '%s/api/agent/install.sh?rebuild=false&base_url=%s\n' \
        "${management_url%/}" \
        "$encoded_base_url"
}

copy_dir_contents() {
    local source_dir="$1"
    local dest_dir="$2"
    mkdir -p "$dest_dir"
    cp -a "$source_dir"/. "$dest_dir"/
}

snapshot_existing_install() {
    local backup_dir="$1"
    local install_root="$2"
    local config_dir="$3"
    local systemd_dir="$4"
    shift 4
    local units=("$@")

    mkdir -p "$backup_dir/systemd"

    if [ -d "$install_root" ]; then
        mkdir -p "$backup_dir/install-root"
        copy_dir_contents "$install_root" "$backup_dir/install-root"
        : > "$backup_dir/install-root.present"
    fi

    if [ -d "$config_dir" ]; then
        mkdir -p "$backup_dir/config-dir"
        copy_dir_contents "$config_dir" "$backup_dir/config-dir"
        : > "$backup_dir/config-dir.present"
    fi

    local unit_name unit_path
    for unit_name in "${units[@]}"; do
        unit_path="$systemd_dir/$unit_name"
        if [ -f "$unit_path" ]; then
            cp -a "$unit_path" "$backup_dir/systemd/$unit_name"
        fi
    done
}

restore_snapshot() {
    local backup_dir="$1"
    local install_root="$2"
    local config_dir="$3"
    local systemd_dir="$4"
    shift 4
    local units=("$@")

    rm -rf "$install_root"
    if [ -f "$backup_dir/install-root.present" ]; then
        mkdir -p "$install_root"
        copy_dir_contents "$backup_dir/install-root" "$install_root"
    fi

    rm -rf "$config_dir"
    if [ -f "$backup_dir/config-dir.present" ]; then
        mkdir -p "$config_dir"
        copy_dir_contents "$backup_dir/config-dir" "$config_dir"
    fi

    local unit_name
    for unit_name in "${units[@]}"; do
        rm -f "$systemd_dir/$unit_name"
        if [ -f "$backup_dir/systemd/$unit_name" ]; then
            cp -a "$backup_dir/systemd/$unit_name" "$systemd_dir/$unit_name"
        fi
    done

    systemctl daemon-reload
}

wait_for_service_active() {
    local service_name="$1"
    local timeout_seconds="$2"
    local interval_seconds="$3"
    local started_at
    started_at="$(date +%s)"
    while true; do
        if systemctl is-active --quiet "$service_name"; then
            return 0
        fi
        if [ $(( $(date +%s) - started_at )) -ge "$timeout_seconds" ]; then
            return 1
        fi
        sleep "$interval_seconds"
    done
}

build_control_probe_payload() {
    python3 - <<'PY' "$1" "$2"
import json, sys
print(
    json.dumps(
        {
            "worker_id": sys.argv[1],
            "worker_token": sys.argv[2],
            "request": {"type": "load_scan_settings"},
        }
    )
)
PY
}

verify_control_connectivity() {
    local runtime_env_file="$1"
    local state_env_file="$2"
    local control_url control_proxy worker_id worker_token payload response_file http_code
    control_url="$(read_env_value "CONTROL_URL" "$runtime_env_file" || true)"
    control_proxy="$(read_env_value "CONTROL_PROXY_URL" "$runtime_env_file" || true)"
    worker_id="$(read_env_value "AGENT_ID" "$runtime_env_file" || true)"
    worker_token="$(read_env_value "AGENT_TOKEN" "$state_env_file" || true)"

    [ -n "$control_url" ] || return 0
    [ -n "$worker_id" ] || return 1
    [ -n "$worker_token" ] || return 1

    payload="$(build_control_probe_payload "$worker_id" "$worker_token")"
    response_file="$(mktemp)"
    if [ -n "$control_proxy" ]; then
        http_code="$(
            curl -sS \
                -o "$response_file" \
                -w '%{http_code}' \
                --connect-timeout 15 \
                --max-time 45 \
                --proxy "$control_proxy" \
                -H 'content-type: application/json' \
                -d "$payload" \
                "${control_url%/}/api/worker/control" || true
        )"
    else
        http_code="$(
            curl -sS \
                -o "$response_file" \
                -w '%{http_code}' \
                --connect-timeout 15 \
                --max-time 45 \
                -H 'content-type: application/json' \
                -d "$payload" \
                "${control_url%/}/api/worker/control" || true
        )"
    fi
    if [ "$http_code" = "200" ] && grep -q '"type":"optional_scan_settings"' "$response_file"; then
        rm -f "$response_file"
        return 0
    fi
    rm -f "$response_file"
    return 1
}

verify_runtime_health() {
    local timeout_seconds="$1"
    local interval_seconds="$2"
    local agent_service_name="$3"
    local tor_service_name="$4"
    local runtime_env_file="$5"
    local state_env_file="$6"
    local started_at
    started_at="$(date +%s)"
    while true; do
        if runtime_env_requires_tor; then
            if ! systemctl is-active --quiet "$tor_service_name"; then
                :
            elif systemctl is-active --quiet "$agent_service_name" \
                && verify_control_connectivity "$runtime_env_file" "$state_env_file"; then
                return 0
            fi
        else
            if systemctl is-active --quiet "$agent_service_name" \
                && verify_control_connectivity "$runtime_env_file" "$state_env_file"; then
                return 0
            fi
        fi
        if [ $(( $(date +%s) - started_at )) -ge "$timeout_seconds" ]; then
            return 1
        fi
        sleep "$interval_seconds"
    done
}

restart_runtime_services() {
    local agent_service_name="$1"
    local tor_service_name="$2"
    local update_path_unit_name="$3"

    systemctl daemon-reload
    if runtime_env_requires_tor; then
        systemctl restart "$tor_service_name" >/dev/null 2>&1 || systemctl start "$tor_service_name"
    fi
    systemctl restart "$agent_service_name" >/dev/null 2>&1 || systemctl start "$agent_service_name"
    systemctl restart "$update_path_unit_name" >/dev/null 2>&1 || systemctl start "$update_path_unit_name" || true
}

prune_old_backups() {
    local backup_root="$1"
    local keep_count="$2"
    [ -d "$backup_root" ] || return 0
    local count=0 path
    while IFS= read -r path; do
        count=$((count + 1))
        if [ "$count" -le "$keep_count" ]; then
            continue
        fi
        rm -rf "$path"
    done < <(find "$backup_root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk '{ $1=""; sub(/^ /, ""); print }')
}

perform_rollback() {
    local backup_dir="$1"
    local install_root="$2"
    local config_dir="$3"
    local systemd_dir="$4"
    local agent_service_name="$5"
    local tor_service_name="$6"
    local update_path_unit_name="$7"
    shift 7
    local units=("$@")

    log_warn "Restoring previous agent version from $backup_dir"
    restore_snapshot "$backup_dir" "$install_root" "$config_dir" "$systemd_dir" "${units[@]}"
    restart_runtime_services "$agent_service_name" "$tor_service_name" "$update_path_unit_name"
}

if [ -f "$RUNTIME_ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$RUNTIME_ENV_FILE"
    set +a
fi

REQUEST_FILE="${AGENT_REMOTE_UPDATE_REQUEST_FILE:-$DEFAULT_REQUEST_FILE}"
STATUS_FILE="${AGENT_REMOTE_UPDATE_STATUS_FILE:-$DEFAULT_STATUS_FILE}"
INSTALLER_URL="$(derive_installer_url || true)"
BACKUP_ROOT="${AGENT_REMOTE_UPDATE_BACKUP_ROOT:-$DEFAULT_BACKUP_ROOT}"
HEALTHCHECK_TIMEOUT_SECONDS="${AGENT_REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS:-120}"
HEALTHCHECK_INTERVAL_SECONDS="${AGENT_REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS:-5}"
ROLLBACK_ON_FAILURE="${AGENT_REMOTE_UPDATE_ROLLBACK_ON_FAILURE:-true}"
AGENT_SERVICE_NAME="${AGENT_REMOTE_UPDATE_AGENT_SERVICE_NAME:-$DEFAULT_AGENT_SERVICE_NAME}"
TOR_SERVICE_NAME="${AGENT_REMOTE_UPDATE_TOR_SERVICE_NAME:-$DEFAULT_TOR_SERVICE_NAME}"
UPDATE_PATH_UNIT_NAME="${AGENT_REMOTE_UPDATE_PATH_UNIT_NAME:-$DEFAULT_UPDATE_PATH_UNIT_NAME}"
INSTALL_ROOT="${INSTALL_ROOT:-$DEFAULT_INSTALL_ROOT}"
CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
SYSTEMD_DIR="${SYSTEMD_UNIT_DIR:-$DEFAULT_SYSTEMD_DIR}"
STATE_ENV_FILE="${AGENT_STATE_FILE:-$DEFAULT_STATE_FILE}"
SYSTEMD_UNITS=(
    "$AGENT_SERVICE_NAME"
    "$TOR_SERVICE_NAME"
    "agentd-remote-update.service"
    "$UPDATE_PATH_UNIT_NAME"
)

[ -f "$REQUEST_FILE" ] || exit 0

TMP_REQUEST="$(mktemp /tmp/agent-remote-update-request-XXXXXX.env)"
cp "$REQUEST_FILE" "$TMP_REQUEST"
rm -f "$REQUEST_FILE"

REQUESTED_AT="$(read_env_value "REQUESTED_AT" "$TMP_REQUEST" || true)"
WORKER_ID="$(read_env_value "WORKER_ID" "$TMP_REQUEST" || true)"

if [ -z "$INSTALLER_URL" ]; then
    write_status "failed" "missing remote update installer URL" "$STATUS_FILE"
    exit 1
fi

case "$INSTALLER_URL" in
    *\?*) INSTALLER_URL="${INSTALLER_URL}&v=$(date +%s)" ;;
    *) INSTALLER_URL="${INSTALLER_URL}?v=$(date +%s)" ;;
esac

INSTALLER_PROXY="${CONTROL_PROXY_URL:-}"
if [ -z "$INSTALLER_PROXY" ]; then
    INSTALLER_PROXY="$(read_env_value "CONTROL_PROXY_URL" "$RUNTIME_ENV_FILE" || true)"
fi

mkdir -p "$BACKUP_ROOT"
ROLLBACK_BACKUP_DIR="$BACKUP_ROOT/update-$(date -u +%Y%m%d%H%M%S)-$$"
log_info "Creating rollback snapshot at $ROLLBACK_BACKUP_DIR"
snapshot_existing_install \
    "$ROLLBACK_BACKUP_DIR" \
    "$INSTALL_ROOT" \
    "$CONFIG_DIR" \
    "$SYSTEMD_DIR" \
    "${SYSTEMD_UNITS[@]}"

write_status "running" "remote update started for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" "$STATUS_FILE"

TMP_SCRIPT="$(mktemp /tmp/agent-remote-update-XXXXXX.sh)"
if [ -n "$INSTALLER_PROXY" ]; then
    if ! curl -fsSL --retry 8 --retry-delay 2 --retry-all-errors --max-time 300 \
        --proxy "$INSTALLER_PROXY" \
        "$INSTALLER_URL" -o "$TMP_SCRIPT"; then
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            perform_rollback \
                "$ROLLBACK_BACKUP_DIR" \
                "$INSTALL_ROOT" \
                "$CONFIG_DIR" \
                "$SYSTEMD_DIR" \
                "$AGENT_SERVICE_NAME" \
                "$TOR_SERVICE_NAME" \
                "$UPDATE_PATH_UNIT_NAME" \
                "${SYSTEMD_UNITS[@]}" || true
        fi
        write_status \
            "failed" \
            "failed to download installer for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
            "$STATUS_FILE"
        exit 1
    fi
else
    if ! curl -fsSL --retry 8 --retry-delay 2 --retry-all-errors --max-time 300 \
        "$INSTALLER_URL" -o "$TMP_SCRIPT"; then
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            perform_rollback \
                "$ROLLBACK_BACKUP_DIR" \
                "$INSTALL_ROOT" \
                "$CONFIG_DIR" \
                "$SYSTEMD_DIR" \
                "$AGENT_SERVICE_NAME" \
                "$TOR_SERVICE_NAME" \
                "$UPDATE_PATH_UNIT_NAME" \
                "${SYSTEMD_UNITS[@]}" || true
        fi
        write_status \
            "failed" \
            "failed to download installer for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
            "$STATUS_FILE"
        exit 1
    fi
fi

if [ -n "$INSTALLER_PROXY" ]; then
    export ALL_PROXY="$INSTALLER_PROXY"
    export HTTP_PROXY="$INSTALLER_PROXY"
    export HTTPS_PROXY="$INSTALLER_PROXY"
    export NO_PROXY=""
fi

if ! SKIP_START=true bash "$TMP_SCRIPT"; then
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        if perform_rollback \
            "$ROLLBACK_BACKUP_DIR" \
            "$INSTALL_ROOT" \
            "$CONFIG_DIR" \
            "$SYSTEMD_DIR" \
            "$AGENT_SERVICE_NAME" \
            "$TOR_SERVICE_NAME" \
            "$UPDATE_PATH_UNIT_NAME" \
            "${SYSTEMD_UNITS[@]}"; then
            write_status \
                "rolled_back" \
                "installer failed; restored previous agent version for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
                "$STATUS_FILE"
            exit 0
        fi
        write_status \
            "rollback_failed" \
            "installer failed and rollback also failed for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
            "$STATUS_FILE"
        exit 1
    fi
    write_status \
        "failed" \
        "installer execution failed for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
        "$STATUS_FILE"
    exit 1
fi

if ! restart_runtime_services "$AGENT_SERVICE_NAME" "$TOR_SERVICE_NAME" "$UPDATE_PATH_UNIT_NAME"; then
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        if perform_rollback \
            "$ROLLBACK_BACKUP_DIR" \
            "$INSTALL_ROOT" \
            "$CONFIG_DIR" \
            "$SYSTEMD_DIR" \
            "$AGENT_SERVICE_NAME" \
            "$TOR_SERVICE_NAME" \
            "$UPDATE_PATH_UNIT_NAME" \
            "${SYSTEMD_UNITS[@]}"; then
            write_status \
                "rolled_back" \
                "new agent version failed to restart; restored previous version for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
                "$STATUS_FILE"
            exit 0
        fi
        write_status \
            "rollback_failed" \
            "new agent version failed to restart and rollback also failed for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
            "$STATUS_FILE"
        exit 1
    fi
    write_status \
        "failed" \
        "new agent version failed to restart for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
        "$STATUS_FILE"
    exit 1
fi

if ! verify_runtime_health \
    "$HEALTHCHECK_TIMEOUT_SECONDS" \
    "$HEALTHCHECK_INTERVAL_SECONDS" \
    "$AGENT_SERVICE_NAME" \
    "$TOR_SERVICE_NAME" \
    "$RUNTIME_ENV_FILE" \
    "$STATE_ENV_FILE"; then
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        if perform_rollback \
            "$ROLLBACK_BACKUP_DIR" \
            "$INSTALL_ROOT" \
            "$CONFIG_DIR" \
            "$SYSTEMD_DIR" \
            "$AGENT_SERVICE_NAME" \
            "$TOR_SERVICE_NAME" \
            "$UPDATE_PATH_UNIT_NAME" \
            "${SYSTEMD_UNITS[@]}"; then
            write_status \
                "rolled_back" \
                "new agent version failed health checks; restored previous version for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
                "$STATUS_FILE"
            exit 0
        fi
        write_status \
            "rollback_failed" \
            "new agent version failed health checks and rollback also failed for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
            "$STATUS_FILE"
        exit 1
    fi
    write_status \
        "failed" \
        "new agent version failed health checks for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
        "$STATUS_FILE"
    exit 1
fi

prune_old_backups "$BACKUP_ROOT" "$BACKUP_KEEP_COUNT"

write_status \
    "success" \
    "remote update applied for ${WORKER_ID:-unknown} ${REQUESTED_AT:-}" \
    "$STATUS_FILE"
