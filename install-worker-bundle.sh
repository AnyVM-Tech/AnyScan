#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="${BUNDLE_ROOT:-$SCRIPT_DIR}"

INSTALL_ROOT="${INSTALL_ROOT:-/opt/agentd}"
BIN_DIR="$INSTALL_ROOT/bin"
EXTENSIONS_DIR="$INSTALL_ROOT/extensions"
CONFIG_DIR="${CONFIG_DIR:-/etc/agentd}"
STATE_DIR="${STATE_DIR:-/var/lib/agentd}"
BOOTSTRAP_ARTIFACT_DIR="${BOOTSTRAP_ARTIFACT_DIR:-$STATE_DIR/artifacts}"
RUNTIME_ENV_FILE="${RUNTIME_ENV_FILE:-$CONFIG_DIR/runtime.env}"
RUNTIME_ENV_TEMPLATE_FILE="${RUNTIME_ENV_TEMPLATE_FILE:-$CONFIG_DIR/runtime.env.template}"
BUNDLED_ENV_SOURCE_FILE="${BUNDLED_ENV_SOURCE_FILE:-$BUNDLE_ROOT/env/runtime.env}"
BUNDLED_ENV_INSTALLED_FILE="${BUNDLED_ENV_INSTALLED_FILE:-$CONFIG_DIR/runtime.env.bundle}"
SYSTEMD_UNIT_SOURCE_FILE="${SYSTEMD_UNIT_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd.service}"
SYSTEMD_UNIT_DEST_FILE="${SYSTEMD_UNIT_DEST_FILE:-/etc/systemd/system/agentd.service}"
AGENT_SERVICE_NAME="${AGENT_SERVICE_NAME:-$(basename "$SYSTEMD_UNIT_DEST_FILE")}"
TOR_SYSTEMD_UNIT_SOURCE_FILE="${TOR_SYSTEMD_UNIT_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-tunnel.service}"
TOR_SYSTEMD_UNIT_DEST_FILE="${TOR_SYSTEMD_UNIT_DEST_FILE:-/etc/systemd/system/agentd-tunnel.service}"
TOR_SERVICE_NAME="${TOR_SERVICE_NAME:-$(basename "$TOR_SYSTEMD_UNIT_DEST_FILE")}"
REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE="${REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-remote-update.service}"
REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE="${REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE:-/etc/systemd/system/agentd-remote-update.service}"
REMOTE_UPDATE_PATH_SOURCE_FILE="${REMOTE_UPDATE_PATH_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-remote-update.path}"
REMOTE_UPDATE_PATH_DEST_FILE="${REMOTE_UPDATE_PATH_DEST_FILE:-/etc/systemd/system/agentd-remote-update.path}"
REMOTE_UPDATE_PATH_UNIT_NAME="${REMOTE_UPDATE_PATH_UNIT_NAME:-$(basename "$REMOTE_UPDATE_PATH_DEST_FILE")}"
SERVICE_USER="${SERVICE_USER:-agentd}"
SERVICE_GROUP="${SERVICE_GROUP:-agentd}"
TOR_RUNTIME_SOURCE_DIR="${TOR_RUNTIME_SOURCE_DIR:-$BUNDLE_ROOT/tor}"
TOR_INSTALL_ROOT="${TOR_INSTALL_ROOT:-$INSTALL_ROOT/tor}"
TOR_BIN_DIR="$TOR_INSTALL_ROOT/bin"
TOR_LIB_DIR="$TOR_INSTALL_ROOT/lib"
TOR_SHARE_DIR="$TOR_INSTALL_ROOT/share"
TOR_WRAPPER_DEST="${TOR_WRAPPER_DEST:-$BIN_DIR/tor}"
TOR_STATE_DIR="${TOR_STATE_DIR:-$STATE_DIR/tor}"
TOR_CONFIG_FILE="${TOR_CONFIG_FILE:-$TOR_STATE_DIR/torrc}"
TOR_SOCKS_PROXY_URL="${TOR_SOCKS_PROXY_URL:-socks5h://127.0.0.1:9050}"
AUTO_ENABLE_SERVICES="${AUTO_ENABLE_SERVICES:-true}"

LOCAL_BOOTSTRAP_MANIFEST_DEST="$EXTENSIONS_DIR/bootstrap-provisioner.json"
LOCAL_BOOTSTRAP_SCRIPT_DEST="$EXTENSIONS_DIR/bootstrap-provisioner.py"
VULNSCANNER_MANIFEST_DEST="$EXTENSIONS_DIR/portscan-adapter.json"
VULNSCANNER_SCRIPT_DEST="$EXTENSIONS_DIR/portscan-adapter.py"
VULNSCANNER_RATE_CONTROLLER_DEST="$EXTENSIONS_DIR/anyscan_rate_controller.py"
VULNSCANNER_BIN_DEST="$BIN_DIR/scanner"
AGENT_STATE_FILE="$STATE_DIR/agent.env"
REMOTE_UPDATE_REQUEST_FILE="${REMOTE_UPDATE_REQUEST_FILE:-$STATE_DIR/remote-update.request}"
REMOTE_UPDATE_STATUS_FILE="${REMOTE_UPDATE_STATUS_FILE:-$STATE_DIR/remote-update.status}"
REMOTE_UPDATE_BACKUP_ROOT="${REMOTE_UPDATE_BACKUP_ROOT:-$STATE_DIR/update-backups}"
REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS="${REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS:-120}"
REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS="${REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS:-5}"
REMOTE_UPDATE_ROLLBACK_ON_FAILURE="${REMOTE_UPDATE_ROLLBACK_ON_FAILURE:-true}"
AGENT_BINARY_SOURCE_FILE="${AGENT_BINARY_SOURCE_FILE:-$BUNDLE_ROOT/bin/agentd}"
AGENT_BINARY_DEST_FILE="${AGENT_BINARY_DEST_FILE:-$BIN_DIR/agentd}"
REMOTE_UPDATE_HELPER_SOURCE_FILE="${REMOTE_UPDATE_HELPER_SOURCE_FILE:-$BUNDLE_ROOT/bin/agentd-remote-update.sh}"
REMOTE_UPDATE_HELPER_DEST_FILE="${REMOTE_UPDATE_HELPER_DEST_FILE:-$BIN_DIR/agentd-remote-update.sh}"
RESERVE_BANDWIDTH_HELPER_SOURCE_FILE="${RESERVE_BANDWIDTH_HELPER_SOURCE_FILE:-$BUNDLE_ROOT/bin/reserve-control-bandwidth.sh}"
RESERVE_BANDWIDTH_HELPER_DEST_FILE="${RESERVE_BANDWIDTH_HELPER_DEST_FILE:-$BIN_DIR/reserve-control-bandwidth.sh}"
TUNE_SCANNER_HOST_HELPER_SOURCE_FILE="${TUNE_SCANNER_HOST_HELPER_SOURCE_FILE:-$BUNDLE_ROOT/bin/tune-scanner-host.sh}"
TUNE_SCANNER_HOST_HELPER_DEST_FILE="${TUNE_SCANNER_HOST_HELPER_DEST_FILE:-$BIN_DIR/tune-scanner-host.sh}"
DEFAULT_REMOTE_UPDATE_INSTALLER_URL="${DEFAULT_REMOTE_UPDATE_INSTALLER_URL:-}"
INSTALL_CONTROL_URL_OVERRIDE="${INSTALL_CONTROL_URL_OVERRIDE:-}"
INSTALL_MANAGEMENT_URL_OVERRIDE="${INSTALL_MANAGEMENT_URL_OVERRIDE:-}"
INSTALL_CONTROL_PROXY_URL_OVERRIDE_SET="${INSTALL_CONTROL_PROXY_URL_OVERRIDE+set}"
INSTALL_CONTROL_PROXY_URL_OVERRIDE="${INSTALL_CONTROL_PROXY_URL_OVERRIDE:-}"

print_banner() {
    printf '═══════════════════════════════════════════════════════════\n'
    printf '               Remote Agent Bundle Installer             \n'
    printf '═══════════════════════════════════════════════════════════\n'
}

upsert_env_value() {
    local key="$1"
    local value="$2"
    local file="$3"
    local tmp
    tmp="$(mktemp)"
    if [ -f "$file" ]; then
        awk -v key="$key" -v value="$value" '
            BEGIN { updated = 0 }
            index($0, key "=") == 1 { print key "=" value; updated = 1; next }
            { print }
            END { if (!updated) print key "=" value }
        ' "$file" >"$tmp"
    else
        printf '%s=%s\n' "$key" "$value" >"$tmp"
    fi
    install -m 0640 "$tmp" "$file"
    rm -f "$tmp"
}

remove_env_value() {
    local key="$1"
    local file="$2"
    [ -f "$file" ] || return 0
    local tmp
    tmp="$(mktemp)"
    awk -v key="$key" 'index($0, key "=") != 1 { print }' "$file" >"$tmp"
    install -m 0640 "$tmp" "$file"
    rm -f "$tmp"
}

env_value() {
    local key="$1"
    local file="$2"
    [ -f "$file" ] || return 1
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

detect_host_cpu_threads() {
    local value
    if command_exists nproc; then
        value="$(nproc 2>/dev/null || true)"
    elif command_exists getconf; then
        value="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
    elif command_exists sysctl; then
        value="$(sysctl -n hw.ncpu 2>/dev/null || true)"
    else
        value=""
    fi
    if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ]; then
        printf '%s\n' "$value"
    else
        printf '1\n'
    fi
}

detect_host_default_interface() {
    local value
    if command_exists ip; then
        value="$(ip route show default 2>/dev/null | awk 'NF { for (i=1; i<=NF; i++) if ($i == "dev" && (i+1) <= NF) { print $(i+1); exit } }' || true)"
    fi
    if [ -z "${value:-}" ] && [ -r /proc/net/route ]; then
        value="$(awk 'NR > 1 && $2 == "00000000" { print $1; exit }' /proc/net/route 2>/dev/null || true)"
    fi
    value="$(printf '%s' "${value:-}" | tr -d '[:space:]')"
    if [ -n "$value" ]; then
        printf '%s\n' "$value"
    fi
}

resolve_preferred_scanner_bin() {
    local existing_value bundled_value
    existing_value="$(env_value "SCANNER_BIN" "$RUNTIME_ENV_FILE" || true)"
    bundled_value="$VULNSCANNER_BIN_DEST"

    if [ -n "$existing_value" ] && [ "$existing_value" != "$bundled_value" ] && [ -x "$existing_value" ]; then
        printf '%s\n' "$existing_value"
        return
    fi

    if [ -x /usr/bin/scanner ]; then
        printf '/usr/bin/scanner\n'
        return
    fi

    if [ -x "$bundled_value" ]; then
        printf '%s\n' "$bundled_value"
        return
    fi
}

apply_host_resource_defaults() {
    local cpu_threads="$1"
    local default_interface preferred_scanner_bin

    default_interface="$(detect_host_default_interface || true)"
    preferred_scanner_bin="$(resolve_preferred_scanner_bin || true)"

    if [ -z "$(env_value "AGENT_MAX_ACTIVE_TASKS" "$RUNTIME_ENV_FILE" || true)" ]; then
        upsert_env_value "AGENT_MAX_ACTIVE_TASKS" "$cpu_threads" "$RUNTIME_ENV_FILE"
    fi

    if [ -z "$(env_value "AGENT_CONCURRENCY" "$RUNTIME_ENV_FILE" || true)" ]; then
        upsert_env_value "AGENT_CONCURRENCY" "$cpu_threads" "$RUNTIME_ENV_FILE"
    fi

    if [ -x "$VULNSCANNER_BIN_DEST" ]; then
        # Fallback rate the scanner adapter uses when a per-scan invocation
        # omits `rate_limit` entirely. The Rust worker always serializes
        # `rate_limit` (including 0) into the invocation, so this fallback
        # currently fires only for direct adapter callers (tests, scripts);
        # for invocations from the worker, `rate_limit=0` means "no --rate
        # flag, scanner runs at its natural ceiling". The worker also reports
        # this value to the control plane as registration metadata so the
        # control plane can pick a reasonable per-scan rate.
        #
        # With ANYSCAN_DYNAMIC_RATE_ENABLED=true (the installer default
        # below) the adapter treats this as the AIMD seed rate when no
        # calibration has been learned yet, ramping each worker toward its
        # natural pps ceiling and persisting the learned value to
        # /var/lib/agentd/rate-calibration.json so subsequent scans skip
        # relearn. 500k pps × ~64-byte SYN ≈ 256 Mbit/s, well under the
        # 1 Gbit ceiling that PR #28's reserve-control-bandwidth.sh sets
        # for the bulk class — the tc reservation is the primary safety
        # net for control-plane heartbeats, not this value. Bench on
        # c6in.xlarge (4 vCPU) shows the bundled scanner sustains ~1.7M
        # pps with sender_threads=4 receivers=1 against an unreachable
        # /24; AIMD converges there from 500k in 3-4 windows. Operators
        # can raise SCANNER_DEFAULT_RATE further if they have measured
        # headroom. Set to 0 to disable the fallback (--rate flag omitted).
        if [ -z "$(env_value "SCANNER_DEFAULT_RATE" "$RUNTIME_ENV_FILE" || true)" ]; then
            upsert_env_value "SCANNER_DEFAULT_RATE" "500000" "$RUNTIME_ENV_FILE"
        fi
        # AIMD dynamic rate adjustment is on by default. The static 500k
        # above is well below the measured 1.76M pps ceiling on c6in.xlarge,
        # so without AIMD new scans would leave most of the NIC unused;
        # AIMD converges to the natural ceiling within a handful of windows.
        if [ -z "$(env_value "ANYSCAN_DYNAMIC_RATE_ENABLED" "$RUNTIME_ENV_FILE" || true)" ]; then
            upsert_env_value "ANYSCAN_DYNAMIC_RATE_ENABLED" "true" "$RUNTIME_ENV_FILE"
        fi
        if [ -z "$(env_value "SCANNER_SENDER_THREADS" "$RUNTIME_ENV_FILE" || true)" ]; then
            upsert_env_value "SCANNER_SENDER_THREADS" "$cpu_threads" "$RUNTIME_ENV_FILE"
        fi
        # PR #13 sets DEFAULT_RECEIVER_THREADS=1 in the python adapter because
        # the AF_PACKET capture queue serializes per-receiver and per-CPU
        # spawning wastes cycles on lock contention without raising capture
        # throughput. Bench against an unreachable /24 confirms 1/2/4 receivers
        # all hit the same ~1.7M pps send ceiling, so default to 1 here.
        if [ -z "$(env_value "SCANNER_RECEIVER_THREADS" "$RUNTIME_ENV_FILE" || true)" ]; then
            upsert_env_value "SCANNER_RECEIVER_THREADS" "1" "$RUNTIME_ENV_FILE"
        fi
        if [ -n "$preferred_scanner_bin" ]; then
            upsert_env_value "SCANNER_BIN" "$preferred_scanner_bin" "$RUNTIME_ENV_FILE"
        fi
        if [ -z "$(env_value "SCANNER_INTERFACE" "$RUNTIME_ENV_FILE" || true)" ] && [ -n "$default_interface" ]; then
            upsert_env_value "SCANNER_INTERFACE" "$default_interface" "$RUNTIME_ENV_FILE"
        fi
    fi

    # Defaults for the egress bandwidth reservation that ExecStartPre installs.
    # These can all be overridden in /etc/agentd/runtime.env after install.
    if [ -z "$(env_value "ANYSCAN_RESERVE_BANDWIDTH_BPS" "$RUNTIME_ENV_FILE" || true)" ]; then
        upsert_env_value "ANYSCAN_RESERVE_BANDWIDTH_BPS" "5000000" "$RUNTIME_ENV_FILE"
    fi
    if [ -z "$(env_value "ANYSCAN_RESERVE_LINK_RATE_BPS" "$RUNTIME_ENV_FILE" || true)" ]; then
        upsert_env_value "ANYSCAN_RESERVE_LINK_RATE_BPS" "1000000000" "$RUNTIME_ENV_FILE"
    fi
    if [ -z "$(env_value "ANYSCAN_RESERVE_INTERFACE" "$RUNTIME_ENV_FILE" || true)" ] && [ -n "$default_interface" ]; then
        upsert_env_value "ANYSCAN_RESERVE_INTERFACE" "$default_interface" "$RUNTIME_ENV_FILE"
    fi
    # Mirror the iface for tune-scanner-host.sh's ip-link txqueuelen call so it
    # does not have to re-detect the default route on every service start.
    if [ -z "$(env_value "ANYSCAN_TUNE_INTERFACE" "$RUNTIME_ENV_FILE" || true)" ] && [ -n "$default_interface" ]; then
        upsert_env_value "ANYSCAN_TUNE_INTERFACE" "$default_interface" "$RUNTIME_ENV_FILE"
    fi
}

apply_scanner_host_tunings() {
    if [ ! -x "$TUNE_SCANNER_HOST_HELPER_DEST_FILE" ]; then
        return 0
    fi
    if [ ! -x "$VULNSCANNER_BIN_DEST" ]; then
        # No scanner installed -> no point bumping kernel queues for it.
        return 0
    fi
    printf '[*] Applying scanner host tunings (sysctl drop-in + txqueuelen)...\n'
    # Run with the runtime env so ANYSCAN_TUNE_* overrides from the operator
    # take effect at install time too. Wrap in a subshell so the sourced env
    # vars do not leak into subsequent install steps. The helper fails open
    # on every error.
    (
        if [ -f "$RUNTIME_ENV_FILE" ]; then
            set -a
            # shellcheck disable=SC1090
            . "$RUNTIME_ENV_FILE" 2>/dev/null || true
            set +a
        fi
        "$TUNE_SCANNER_HOST_HELPER_DEST_FILE" apply || true
    )
}

detect_existing_install() {
    [ -x "$AGENT_BINARY_DEST_FILE" ] \
        || [ -f "$RUNTIME_ENV_FILE" ] \
        || [ -f "$AGENT_STATE_FILE" ] \
        || [ -f "$SYSTEMD_UNIT_DEST_FILE" ]
}

preserve_existing_identity() {
    local existing_agent_id existing_agent_name existing_agent_token
    existing_agent_id="$(env_value "AGENT_ID" "$RUNTIME_ENV_FILE" || true)"
    existing_agent_name="$(env_value "AGENT_NAME" "$RUNTIME_ENV_FILE" || true)"
    existing_agent_token="$(env_value "AGENT_TOKEN" "$AGENT_STATE_FILE" || true)"

    if [ -n "$existing_agent_id" ]; then
        upsert_env_value "AGENT_ID" "$existing_agent_id" "$RUNTIME_ENV_FILE"
    fi
    if [ -n "$existing_agent_name" ]; then
        upsert_env_value "AGENT_NAME" "$existing_agent_name" "$RUNTIME_ENV_FILE"
    fi

    if [ -n "$existing_agent_token" ]; then
        remove_env_value "AGENT_BOOTSTRAP_CODE" "$RUNTIME_ENV_FILE"
        remove_env_value "AGENT_BOOTSTRAP_CODE_OBFUSCATED" "$RUNTIME_ENV_FILE"
        remove_env_value "AGENT_BOOTSTRAP_CODE_OBFUSCATION" "$RUNTIME_ENV_FILE"
    fi
}

restart_managed_services() {
    local existing_install="$1"

    if [ "$AUTO_ENABLE_SERVICES" != "true" ]; then
        return 0
    fi

    if runtime_env_requires_tor && [ -f "$TOR_SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '[*] %s bundled network proxy...\n' "$([ "$existing_install" = "true" ] && printf 'Restarting' || printf 'Enabling and starting')"
        systemctl enable --now "$TOR_SERVICE_NAME"
        systemctl restart "$TOR_SERVICE_NAME"
    fi

    if [ -f "$REMOTE_UPDATE_PATH_DEST_FILE" ]; then
        printf '[*] %s %s for remote self-updates...\n' \
            "$([ "$existing_install" = "true" ] && printf 'Restarting' || printf 'Enabling and starting')" \
            "$REMOTE_UPDATE_PATH_UNIT_NAME"
        systemctl enable --now "$REMOTE_UPDATE_PATH_UNIT_NAME"
        systemctl restart "$REMOTE_UPDATE_PATH_UNIT_NAME" || true
    fi

    if [ -f "$SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '[*] %s %s...\n' \
            "$([ "$existing_install" = "true" ] && printf 'Restarting' || printf 'Enabling and starting')" \
            "$AGENT_SERVICE_NAME"
        systemctl enable --now "$AGENT_SERVICE_NAME"
        systemctl restart "$AGENT_SERVICE_NAME"
    fi
}

materialize_runtime_env() {
    local source_file="$1"
    local dest_file="$2"

    install -m 0640 "$source_file" "$dest_file"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

runtime_env_requires_tor() {
    local api_base_url api_proxy_url
    api_base_url="$(env_value "CONTROL_URL" "$RUNTIME_ENV_FILE" || true)"
    api_proxy_url="$(env_value "CONTROL_PROXY_URL" "$RUNTIME_ENV_FILE" || true)"
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

install_bundled_tor_runtime() {
    if [ ! -f "$TOR_RUNTIME_SOURCE_DIR/bin/tor.real" ]; then
        return 1
    fi

    printf '[*] Installing bundled Tor runtime...\n'
    install -d -m 0755 "$TOR_INSTALL_ROOT" "$TOR_BIN_DIR" "$TOR_LIB_DIR" "$TOR_SHARE_DIR"
    install -m 0755 "$TOR_RUNTIME_SOURCE_DIR/bin/tor.real" "$TOR_BIN_DIR/tor.real"

    local tor_file base_name mode
    if [ -d "$TOR_RUNTIME_SOURCE_DIR/lib" ]; then
        for tor_file in "$TOR_RUNTIME_SOURCE_DIR"/lib/*; do
            [ -f "$tor_file" ] || continue
            base_name="$(basename "$tor_file")"
            mode="0644"
            case "$base_name" in
                ld-linux*|ld-musl*)
                    mode="0755"
                    ;;
            esac
            install -m "$mode" "$tor_file" "$TOR_LIB_DIR/$base_name"
        done
    fi

    for tor_file in geoip geoip6; do
        if [ -f "$TOR_RUNTIME_SOURCE_DIR/share/$tor_file" ]; then
            install -m 0644 "$TOR_RUNTIME_SOURCE_DIR/share/$tor_file" "$TOR_SHARE_DIR/$tor_file"
        fi
    done
}

write_tor_wrapper() {
    cat >"$TOR_WRAPPER_DEST" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TOR_ROOT="${TOR_INSTALL_ROOT}"
TOR_REAL="\$TOR_ROOT/bin/tor.real"
TOR_LIB="\$TOR_ROOT/lib"
loader=""

for candidate in "\$TOR_LIB"/ld-linux* "\$TOR_LIB"/ld-musl*; do
    if [ -x "\$candidate" ]; then
        loader="\$candidate"
        break
    fi
done

if [ -n "\$loader" ]; then
    exec "\$loader" --library-path "\$TOR_LIB" "\$TOR_REAL" "\$@"
fi

export LD_LIBRARY_PATH="\$TOR_LIB\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "\$TOR_REAL" "\$@"
EOF
    chmod 0755 "$TOR_WRAPPER_DEST"
}

write_tor_config() {
    cat >"$TOR_CONFIG_FILE" <<EOF
# Bundled Tor client for onion control-channel access
ClientOnly 1
DataDirectory ${TOR_STATE_DIR}
SocksPort 127.0.0.1:9050
AvoidDiskWrites 1
Log notice stderr
EOF
    if [ -f "$TOR_SHARE_DIR/geoip" ]; then
        printf 'GeoIPFile %s\n' "$TOR_SHARE_DIR/geoip" >>"$TOR_CONFIG_FILE"
    fi
    if [ -f "$TOR_SHARE_DIR/geoip6" ]; then
        printf 'GeoIPv6File %s\n' "$TOR_SHARE_DIR/geoip6" >>"$TOR_CONFIG_FILE"
    fi
    chmod 0640 "$TOR_CONFIG_FILE"
}

validate_bundled_tor_runtime() {
    if [ ! -x "$TOR_WRAPPER_DEST" ]; then
        return 0
    fi

    printf '[*] Validating bundled Tor runtime...\n'
    local validation_log
    validation_log="$(mktemp)"
    if ! runuser -u "$SERVICE_USER" -- "$TOR_WRAPPER_DEST" --version >"$validation_log" 2>&1; then
        cat "$validation_log" >&2 || true
        rm -f "$validation_log"
        return 1
    fi
    if ! runuser -u "$SERVICE_USER" -- "$TOR_WRAPPER_DEST" --verify-config -f "$TOR_CONFIG_FILE" >"$validation_log" 2>&1; then
        cat "$validation_log" >&2 || true
        rm -f "$validation_log"
        return 1
    fi
    rm -f "$validation_log"
}

enable_bundled_tor_service() {
    if [ ! -f "$TOR_SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '[!] Bundled Tor systemd unit was not installed.\n' >&2
        exit 1
    fi
    printf '[*] Enabling %s for onion control-channel connectivity...\n' "$(basename "$TOR_SYSTEMD_UNIT_DEST_FILE")"
    systemctl enable --now "$(basename "$TOR_SYSTEMD_UNIT_DEST_FILE")"
    systemctl restart "$(basename "$TOR_SYSTEMD_UNIT_DEST_FILE")"
}

main() {
    print_banner
    local existing_install="false"

    if [ "$EUID" -ne 0 ]; then
        printf '[!] Please run as root.\n' >&2
        exit 1
    fi

    if [ ! -f "$AGENT_BINARY_SOURCE_FILE" ]; then
        printf '[!] Missing agent binary at %s\n' "$AGENT_BINARY_SOURCE_FILE" >&2
        exit 1
    fi

    if detect_existing_install; then
        existing_install="true"
        printf '[*] Existing agent installation detected; applying in-place update.\n'
    fi

    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        printf '[*] Creating service user %s...\n' "$SERVICE_USER"
        useradd --system --user-group --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi

    # Grant the service user read access to the systemd journal so operators
    # (and remote-debug commands routed via the API) can tail `journalctl -u
    # agentd` as $SERVICE_USER. The unit runs with NoNewPrivileges=true, so
    # `sudo journalctl` from inside the service is blocked; group membership
    # is the supported route. Idempotent: only adds when the group exists
    # locally and the user is not already a member.
    if getent group systemd-journal >/dev/null 2>&1; then
        if ! id -nG "$SERVICE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx systemd-journal; then
            printf '[*] Adding %s to systemd-journal group for journalctl access...\n' "$SERVICE_USER"
            usermod -aG systemd-journal "$SERVICE_USER"
        fi
    fi

    printf '[*] Creating install directories...\n'
    install -d -m 0755 "$INSTALL_ROOT" "$BIN_DIR" "$EXTENSIONS_DIR"
    install -d -m 0755 "$EXTENSIONS_DIR/bundled" "$EXTENSIONS_DIR/bundled/manifests" "$EXTENSIONS_DIR/bundled/rules" "$EXTENSIONS_DIR/bundled/scripts"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR" "$BOOTSTRAP_ARTIFACT_DIR" "$TOR_STATE_DIR"
    install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR"

    printf '[*] Installing agent runtime...\n'
    install -m 0755 "$AGENT_BINARY_SOURCE_FILE" "$AGENT_BINARY_DEST_FILE"
    if [ -f "$REMOTE_UPDATE_HELPER_SOURCE_FILE" ]; then
        install -m 0755 "$REMOTE_UPDATE_HELPER_SOURCE_FILE" "$REMOTE_UPDATE_HELPER_DEST_FILE"
    fi
    if [ -f "$RESERVE_BANDWIDTH_HELPER_SOURCE_FILE" ]; then
        install -m 0755 "$RESERVE_BANDWIDTH_HELPER_SOURCE_FILE" "$RESERVE_BANDWIDTH_HELPER_DEST_FILE"
    fi
    if [ -f "$TUNE_SCANNER_HOST_HELPER_SOURCE_FILE" ]; then
        install -m 0755 "$TUNE_SCANNER_HOST_HELPER_SOURCE_FILE" "$TUNE_SCANNER_HOST_HELPER_DEST_FILE"
    fi

    printf '[*] Installing extension assets...\n'
    install -m 0644 "$BUNDLE_ROOT/extensions/bootstrap-provisioner.json" "$LOCAL_BOOTSTRAP_MANIFEST_DEST"
    install -m 0755 "$BUNDLE_ROOT/extensions/bootstrap-provisioner.py" "$LOCAL_BOOTSTRAP_SCRIPT_DEST"
    install -m 0644 "$BUNDLE_ROOT/extensions/portscan-adapter.json" "$VULNSCANNER_MANIFEST_DEST"
    install -m 0755 "$BUNDLE_ROOT/extensions/portscan-adapter.py" "$VULNSCANNER_SCRIPT_DEST"
    if [ -f "$BUNDLE_ROOT/extensions/anyscan_rate_controller.py" ]; then
        install -m 0644 "$BUNDLE_ROOT/extensions/anyscan_rate_controller.py" "$VULNSCANNER_RATE_CONTROLLER_DEST"
    fi
    cp -R "$BUNDLE_ROOT/extensions/bundled/manifests/." "$EXTENSIONS_DIR/bundled/manifests/"
    cp -R "$BUNDLE_ROOT/extensions/bundled/rules/." "$EXTENSIONS_DIR/bundled/rules/"
    cp -R "$BUNDLE_ROOT/extensions/bundled/scripts/." "$EXTENSIONS_DIR/bundled/scripts/"
    chmod 0755 "$EXTENSIONS_DIR"/bundled/scripts/*.py

    local extension_manifests="$LOCAL_BOOTSTRAP_MANIFEST_DEST"
    if [ -f "$BUNDLE_ROOT/bin/scanner" ]; then
        printf '[*] Installing bundled scanner binary...\n'
        install -m 0755 "$BUNDLE_ROOT/bin/scanner" "$VULNSCANNER_BIN_DEST"
        extension_manifests="$extension_manifests,$VULNSCANNER_MANIFEST_DEST"
    else
        printf '[*] No bundled scanner binary found; the agent will install without port-scan adapter support.\n'
    fi

    if install_bundled_tor_runtime; then
        write_tor_wrapper
        write_tor_config
        chown "$SERVICE_USER":"$SERVICE_GROUP" "$TOR_CONFIG_FILE"
        validate_bundled_tor_runtime
    fi

    printf '[*] Installing runtime env template...\n'
    install -m 0640 "$BUNDLE_ROOT/env/runtime.env.template" "$RUNTIME_ENV_TEMPLATE_FILE"
    if [ -f "$BUNDLED_ENV_SOURCE_FILE" ]; then
        install -m 0640 "$BUNDLED_ENV_SOURCE_FILE" "$BUNDLED_ENV_INSTALLED_FILE"
    fi
    if [ ! -f "$RUNTIME_ENV_FILE" ]; then
        if [ -f "$BUNDLED_ENV_SOURCE_FILE" ]; then
            materialize_runtime_env "$BUNDLED_ENV_SOURCE_FILE" "$RUNTIME_ENV_FILE"
        else
            install -m 0640 "$BUNDLE_ROOT/env/runtime.env.template" "$RUNTIME_ENV_FILE"
        fi
    fi
    if [ ! -f "$AGENT_STATE_FILE" ]; then
        install -m 0640 /dev/null "$AGENT_STATE_FILE"
    fi

    printf '[*] Updating agent runtime env defaults in %s...\n' "$RUNTIME_ENV_FILE"
    local bundled_bundle_name
    local cpu_threads
    cpu_threads="$(detect_host_cpu_threads)"
    bundled_bundle_name="$(env_value "AGENT_BUNDLE_NAME" "$BUNDLED_ENV_SOURCE_FILE" || true)"
    upsert_env_value "EXTENSION_MANIFEST_PATHS" "$extension_manifests" "$RUNTIME_ENV_FILE"
    upsert_env_value "ARTIFACT_DIR" "$BOOTSTRAP_ARTIFACT_DIR" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_STATE_FILE" "$AGENT_STATE_FILE" "$RUNTIME_ENV_FILE"
    if [ -n "$bundled_bundle_name" ]; then
        upsert_env_value "AGENT_BUNDLE_NAME" "$bundled_bundle_name" "$RUNTIME_ENV_FILE"
    fi
    if [ -n "$INSTALL_CONTROL_URL_OVERRIDE" ]; then
        upsert_env_value "CONTROL_URL" "$INSTALL_CONTROL_URL_OVERRIDE" "$RUNTIME_ENV_FILE"
    fi
    local management_url
    management_url="$INSTALL_MANAGEMENT_URL_OVERRIDE"
    if [ -z "$management_url" ]; then
        management_url="$(env_value "AGENT_MANAGEMENT_URL" "$RUNTIME_ENV_FILE" || true)"
    fi
    if [ -z "$management_url" ]; then
        management_url="$(env_value "CONTROL_URL" "$RUNTIME_ENV_FILE" || true)"
    fi
    if [ -n "$management_url" ]; then
        upsert_env_value "AGENT_MANAGEMENT_URL" "$management_url" "$RUNTIME_ENV_FILE"
    fi
    if [ -n "$INSTALL_CONTROL_PROXY_URL_OVERRIDE_SET" ]; then
        if [ -n "$INSTALL_CONTROL_PROXY_URL_OVERRIDE" ]; then
            upsert_env_value "CONTROL_PROXY_URL" "$INSTALL_CONTROL_PROXY_URL_OVERRIDE" "$RUNTIME_ENV_FILE"
        else
            remove_env_value "CONTROL_PROXY_URL" "$RUNTIME_ENV_FILE"
        fi
    fi
    upsert_env_value "AGENT_REMOTE_UPDATE_ENABLED" "true" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_UPDATE_REQUEST_FILE" "$REMOTE_UPDATE_REQUEST_FILE" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_UPDATE_STATUS_FILE" "$REMOTE_UPDATE_STATUS_FILE" "$RUNTIME_ENV_FILE"
    if [ -n "$DEFAULT_REMOTE_UPDATE_INSTALLER_URL" ]; then
        upsert_env_value "AGENT_REMOTE_UPDATE_INSTALLER_URL" "$DEFAULT_REMOTE_UPDATE_INSTALLER_URL" "$RUNTIME_ENV_FILE"
    fi
    upsert_env_value "AGENT_REMOTE_UPDATE_BACKUP_ROOT" "$REMOTE_UPDATE_BACKUP_ROOT" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS" "$REMOTE_UPDATE_HEALTHCHECK_TIMEOUT_SECONDS" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS" "$REMOTE_UPDATE_HEALTHCHECK_INTERVAL_SECONDS" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_UPDATE_ROLLBACK_ON_FAILURE" "$REMOTE_UPDATE_ROLLBACK_ON_FAILURE" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_REMOTE_DEBUG_ENABLED" "true" "$RUNTIME_ENV_FILE"
    if [ -x "$VULNSCANNER_BIN_DEST" ]; then
        upsert_env_value "SCANNER_BIN" "$VULNSCANNER_BIN_DEST" "$RUNTIME_ENV_FILE"
    fi

    if runtime_env_requires_tor; then
        if [ ! -x "$TOR_WRAPPER_DEST" ]; then
            printf '[!] This bundle requires Tor for onion connectivity, but no bundled Tor runtime was installed.\n' >&2
            exit 1
        fi
        upsert_env_value "CONTROL_PROXY_URL" "$TOR_SOCKS_PROXY_URL" "$RUNTIME_ENV_FILE"
    fi

    apply_host_resource_defaults "$cpu_threads"
    apply_scanner_host_tunings

    if [ "$existing_install" = "true" ]; then
        preserve_existing_identity
    fi

    chown root:"$SERVICE_GROUP" "$CONFIG_DIR" "$RUNTIME_ENV_FILE" "$RUNTIME_ENV_TEMPLATE_FILE"
    chmod 0750 "$CONFIG_DIR"
    chown "$SERVICE_USER":"$SERVICE_GROUP" "$AGENT_STATE_FILE" "$TOR_STATE_DIR"
    if [ -f "$BUNDLED_ENV_INSTALLED_FILE" ]; then
        chown root:"$SERVICE_GROUP" "$BUNDLED_ENV_INSTALLED_FILE"
    fi
    if [ -f "$TOR_CONFIG_FILE" ]; then
        chown "$SERVICE_USER":"$SERVICE_GROUP" "$TOR_CONFIG_FILE"
    fi

    if [ -f "$SYSTEMD_UNIT_SOURCE_FILE" ]; then
        printf '[*] Installing systemd unit %s...\n' "$SYSTEMD_UNIT_DEST_FILE"
        install -d -m 0755 "$(dirname "$SYSTEMD_UNIT_DEST_FILE")"
        install -m 0644 "$SYSTEMD_UNIT_SOURCE_FILE" "$SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$TOR_SYSTEMD_UNIT_SOURCE_FILE" ]; then
        printf '[*] Installing systemd unit %s...\n' "$TOR_SYSTEMD_UNIT_DEST_FILE"
        install -d -m 0755 "$(dirname "$TOR_SYSTEMD_UNIT_DEST_FILE")"
        install -m 0644 "$TOR_SYSTEMD_UNIT_SOURCE_FILE" "$TOR_SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE" ]; then
        printf '[*] Installing systemd unit %s...\n' "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE"
        install -d -m 0755 "$(dirname "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE")"
        install -m 0644 "$REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE" "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$REMOTE_UPDATE_PATH_SOURCE_FILE" ]; then
        printf '[*] Installing systemd unit %s...\n' "$REMOTE_UPDATE_PATH_DEST_FILE"
        install -d -m 0755 "$(dirname "$REMOTE_UPDATE_PATH_DEST_FILE")"
        install -m 0644 "$REMOTE_UPDATE_PATH_SOURCE_FILE" "$REMOTE_UPDATE_PATH_DEST_FILE"
    fi
    if [ -f "$SYSTEMD_UNIT_DEST_FILE" ] || [ -f "$TOR_SYSTEMD_UNIT_DEST_FILE" ] || [ -f "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE" ] || [ -f "$REMOTE_UPDATE_PATH_DEST_FILE" ]; then
        systemctl daemon-reload
    fi
    restart_managed_services "$existing_install"

    printf '\nInstall complete.\n\n'
    printf 'Installed files:\n'
    printf '  agent binary: %s\n' "$AGENT_BINARY_DEST_FILE"
    if [ -x "$VULNSCANNER_BIN_DEST" ]; then
        printf '  scanner binary: %s\n' "$VULNSCANNER_BIN_DEST"
    fi
    printf '  runtime env: %s\n' "$RUNTIME_ENV_FILE"
    printf '  env template: %s\n' "$RUNTIME_ENV_TEMPLATE_FILE"
    if [ -x "$TOR_WRAPPER_DEST" ]; then
        printf '  bundled tor wrapper: %s\n' "$TOR_WRAPPER_DEST"
        printf '  tor config: %s\n' "$TOR_CONFIG_FILE"
    fi
    if [ -x "$REMOTE_UPDATE_HELPER_DEST_FILE" ]; then
        printf '  update helper: %s\n' "$REMOTE_UPDATE_HELPER_DEST_FILE"
    fi
    if [ -f "$BUNDLED_ENV_INSTALLED_FILE" ]; then
        printf '  bundled env: %s\n' "$BUNDLED_ENV_INSTALLED_FILE"
    fi
    if [ -f "$SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '  systemd unit: %s\n' "$SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$TOR_SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '  tor systemd unit: %s\n' "$TOR_SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE" ]; then
        printf '  update systemd unit: %s\n' "$REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE"
    fi
    if [ -f "$REMOTE_UPDATE_PATH_DEST_FILE" ]; then
        printf '  update path unit: %s\n' "$REMOTE_UPDATE_PATH_DEST_FILE"
    fi
    if [ "$existing_install" = "true" ]; then
        printf '\nUpdate summary:\n'
        printf '  Existing worker identity and persisted token were preserved when present.\n'
        printf '  Managed services were reloaded/restarted in place.\n'
        printf '  Review %s only if you want to override the current control URL, agent id, pool, tags, or proxy.\n' "$RUNTIME_ENV_FILE"
    else
        printf '\nNext steps:\n'
        printf '  1. Start manually for validation:\n'
        printf '       set -a && source %s && set +a && %s daemon\n' "$RUNTIME_ENV_FILE" "$AGENT_BINARY_DEST_FILE"
        printf '  2. Or run it as a service:\n'
        printf '       systemctl enable --now %s\n' "$AGENT_SERVICE_NAME"
        printf '  3. Review %s only if you want to override the preset control URL, agent id, pool, tags, or proxy.\n' "$RUNTIME_ENV_FILE"
    fi
}

main "$@"
