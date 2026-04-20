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
TOR_SYSTEMD_UNIT_SOURCE_FILE="${TOR_SYSTEMD_UNIT_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-tunnel.service}"
TOR_SYSTEMD_UNIT_DEST_FILE="${TOR_SYSTEMD_UNIT_DEST_FILE:-/etc/systemd/system/agentd-tunnel.service}"
REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE="${REMOTE_UPDATE_SYSTEMD_UNIT_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-remote-update.service}"
REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE="${REMOTE_UPDATE_SYSTEMD_UNIT_DEST_FILE:-/etc/systemd/system/agentd-remote-update.service}"
REMOTE_UPDATE_PATH_SOURCE_FILE="${REMOTE_UPDATE_PATH_SOURCE_FILE:-$BUNDLE_ROOT/systemd/agentd-remote-update.path}"
REMOTE_UPDATE_PATH_DEST_FILE="${REMOTE_UPDATE_PATH_DEST_FILE:-/etc/systemd/system/agentd-remote-update.path}"
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
DEFAULT_REMOTE_UPDATE_INSTALLER_URL="${DEFAULT_REMOTE_UPDATE_INSTALLER_URL:-}"

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

    if [ "$EUID" -ne 0 ]; then
        printf '[!] Please run as root.\n' >&2
        exit 1
    fi

    if [ ! -f "$AGENT_BINARY_SOURCE_FILE" ]; then
        printf '[!] Missing agent binary at %s\n' "$AGENT_BINARY_SOURCE_FILE" >&2
        exit 1
    fi

    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        printf '[*] Creating service user %s...\n' "$SERVICE_USER"
        useradd --system --user-group --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
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

    printf '[*] Installing extension assets...\n'
    install -m 0644 "$BUNDLE_ROOT/extensions/bootstrap-provisioner.json" "$LOCAL_BOOTSTRAP_MANIFEST_DEST"
    install -m 0755 "$BUNDLE_ROOT/extensions/bootstrap-provisioner.py" "$LOCAL_BOOTSTRAP_SCRIPT_DEST"
    install -m 0644 "$BUNDLE_ROOT/extensions/portscan-adapter.json" "$VULNSCANNER_MANIFEST_DEST"
    install -m 0755 "$BUNDLE_ROOT/extensions/portscan-adapter.py" "$VULNSCANNER_SCRIPT_DEST"
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
    upsert_env_value "EXTENSION_MANIFEST_PATHS" "$extension_manifests" "$RUNTIME_ENV_FILE"
    upsert_env_value "ARTIFACT_DIR" "$BOOTSTRAP_ARTIFACT_DIR" "$RUNTIME_ENV_FILE"
    upsert_env_value "AGENT_STATE_FILE" "$AGENT_STATE_FILE" "$RUNTIME_ENV_FILE"
    local management_url
    management_url="$(env_value "AGENT_MANAGEMENT_URL" "$RUNTIME_ENV_FILE" || true)"
    if [ -z "$management_url" ]; then
        management_url="$(env_value "CONTROL_URL" "$RUNTIME_ENV_FILE" || true)"
    fi
    if [ -n "$management_url" ]; then
        upsert_env_value "AGENT_MANAGEMENT_URL" "$management_url" "$RUNTIME_ENV_FILE"
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
    if [ "$AUTO_ENABLE_SERVICES" = "true" ] && runtime_env_requires_tor; then
        enable_bundled_tor_service
    fi
    if [ "$AUTO_ENABLE_SERVICES" = "true" ] && [ -f "$REMOTE_UPDATE_PATH_DEST_FILE" ]; then
        printf '[*] Enabling %s for remote self-updates...\n' "$(basename "$REMOTE_UPDATE_PATH_DEST_FILE")"
        systemctl enable --now "$(basename "$REMOTE_UPDATE_PATH_DEST_FILE")"
    fi

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
    printf '\nNext steps:\n'
    printf '  1. Start manually for validation:\n'
    printf '       set -a && source %s && set +a && %s daemon\n' "$RUNTIME_ENV_FILE" "$AGENT_BINARY_DEST_FILE"
    printf '  2. Or run it as a service:\n'
    printf '       systemctl enable --now %s\n' "$(basename "$SYSTEMD_UNIT_DEST_FILE")"
    printf '  3. Review %s only if you want to override the preset control URL, agent id, pool, tags, or proxy.\n' "$RUNTIME_ENV_FILE"
}

main "$@"
