#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUNDLE_INPUT="${1:-}"
CHECKSUM_INPUT="${2:-}"
SKIP_CHECKSUM="${SKIP_CHECKSUM:-false}"
SKIP_START="${SKIP_START:-false}"
KEEP_EXTRACTED="${KEEP_EXTRACTED:-false}"

EXTRACT_ROOT=""
BUNDLE_DIR=""
TOR_SERVICE_WAIT_SECONDS="${TOR_SERVICE_WAIT_SECONDS:-120}"
AGENT_SERVICE_WAIT_SECONDS="${AGENT_SERVICE_WAIT_SECONDS:-120}"
AGENT_TOKEN_WAIT_SECONDS="${AGENT_TOKEN_WAIT_SECONDS:-300}"

print_banner() {
    printf '═══════════════════════════════════════════════════════════\n'
    printf '              Remote Agent Host Bootstrap                \n'
    printf '═══════════════════════════════════════════════════════════\n'
}

info() {
    printf '[*] %s\n' "$1"
}

warn() {
    printf '[!] %s\n' "$1" >&2
}

fail() {
    printf '[!] %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  sudo ./bootstrap-agent-host.sh [bundle.tar.gz] [bundle.sha256]

Behavior:
  - If run inside an extracted agent bundle, no arguments are required.
  - If a tarball path is provided, the script verifies it, extracts it, installs it,
    starts the services, and runs sanity checks.

Environment overrides:
  SKIP_CHECKSUM=true   Skip checksum verification
  SKIP_START=true      Install only; do not enable/start services
  KEEP_EXTRACTED=true  Keep the temporary extracted directory after completion
EOF
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

unique_append() {
    local item="$1"
    shift
    local current
    for current in "$@"; do
        if [ "$current" = "$item" ]; then
            return 0
        fi
    done
    return 1
}

detect_package_manager() {
    if command_exists apt-get; then
        printf 'apt\n'
    elif command_exists dnf; then
        printf 'dnf\n'
    elif command_exists yum; then
        printf 'yum\n'
    elif command_exists pacman; then
        printf 'pacman\n'
    elif command_exists zypper; then
        printf 'zypper\n'
    elif command_exists apk; then
        printf 'apk\n'
    else
        printf 'unknown\n'
    fi
}

package_for_command() {
    local manager="$1"
    local command_name="$2"

    case "$manager" in
        apt)
            case "$command_name" in
                python3) printf 'python3\n' ;;
                curl) printf 'curl\n' ;;
                tar) printf 'tar\n' ;;
                sha256sum|mktemp|install|id) printf 'coreutils\n' ;;
                awk) printf 'gawk\n' ;;
                grep) printf 'grep\n' ;;
                sed) printf 'sed\n' ;;
                useradd) printf 'passwd\n' ;;
                systemctl|journalctl) printf 'systemd\n' ;;
                ldd) printf 'libc-bin\n' ;;
                ss) printf 'iproute2\n' ;;
            esac
            ;;
        dnf|yum)
            case "$command_name" in
                python3) printf 'python3\n' ;;
                curl) printf 'curl\n' ;;
                tar) printf 'tar\n' ;;
                sha256sum|mktemp|install|id) printf 'coreutils\n' ;;
                awk) printf 'gawk\n' ;;
                grep) printf 'grep\n' ;;
                sed) printf 'sed\n' ;;
                useradd) printf 'shadow-utils\n' ;;
                systemctl|journalctl) printf 'systemd\n' ;;
                ldd) printf 'glibc\n' ;;
                ss) printf 'iproute\n' ;;
            esac
            ;;
        pacman)
            case "$command_name" in
                python3) printf 'python\n' ;;
                curl) printf 'curl\n' ;;
                tar) printf 'tar\n' ;;
                sha256sum|mktemp|install|id) printf 'coreutils\n' ;;
                awk) printf 'gawk\n' ;;
                grep) printf 'grep\n' ;;
                sed) printf 'sed\n' ;;
                useradd) printf 'shadow\n' ;;
                systemctl|journalctl) printf 'systemd\n' ;;
                ldd) printf 'glibc\n' ;;
                ss) printf 'iproute2\n' ;;
            esac
            ;;
        zypper)
            case "$command_name" in
                python3) printf 'python3\n' ;;
                curl) printf 'curl\n' ;;
                tar) printf 'tar\n' ;;
                sha256sum|mktemp|install|id) printf 'coreutils\n' ;;
                awk) printf 'gawk\n' ;;
                grep) printf 'grep\n' ;;
                sed) printf 'sed\n' ;;
                useradd) printf 'shadow\n' ;;
                systemctl|journalctl) printf 'systemd\n' ;;
                ldd) printf 'glibc\n' ;;
                ss) printf 'iproute2\n' ;;
            esac
            ;;
        apk)
            case "$command_name" in
                python3) printf 'python3\n' ;;
                curl) printf 'curl\n' ;;
                tar) printf 'tar\n' ;;
                sha256sum|mktemp|install|id) printf 'coreutils\n' ;;
                awk) printf 'gawk\n' ;;
                grep) printf 'grep\n' ;;
                sed) printf 'sed\n' ;;
                useradd) printf 'shadow\n' ;;
                systemctl|journalctl) printf 'systemd\n' ;;
                ldd) printf 'libc-utils\n' ;;
                ss) printf 'iproute2\n' ;;
            esac
            ;;
    esac
}

install_packages() {
    local manager="$1"
    shift
    [ "$#" -gt 0 ] || return 0

    info "Installing host packages: $*"
    case "$manager" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y "$@"
            ;;
        dnf)
            dnf install -y "$@"
            ;;
        yum)
            yum install -y "$@"
            ;;
        pacman)
            pacman -Sy --noconfirm "$@"
            ;;
        zypper)
            zypper --non-interactive install "$@"
            ;;
        apk)
            fail "Alpine/apk hosts are not supported for this bundle because the agent binary expects glibc and systemd."
            ;;
        *)
            fail "No supported package manager was found to install host dependencies."
            ;;
    esac
}

ensure_host_prereqs() {
    local manager required_commands missing_commands packages command_name package_name
    manager="$(detect_package_manager)"

    required_commands=(
        python3
        curl
        tar
        sha256sum
        awk
        grep
        sed
        mktemp
        install
        id
        useradd
        systemctl
        journalctl
        ldd
        ss
    )

    missing_commands=()
    for command_name in "${required_commands[@]}"; do
        if ! command_exists "$command_name"; then
            missing_commands+=("$command_name")
        fi
    done

    [ "${#missing_commands[@]}" -gt 0 ] || return 0
    packages=()
    for command_name in "${missing_commands[@]}"; do
        package_name="$(package_for_command "$manager" "$command_name" || true)"
        if [ -n "$package_name" ] && ! unique_append "$package_name" "${packages[@]:-}"; then
            packages+=("$package_name")
        fi
    done

    if [ "${#packages[@]}" -gt 0 ]; then
        install_packages "$manager" "${packages[@]}"
    fi

    for command_name in "${missing_commands[@]}"; do
        command_exists "$command_name" || fail "required host command is still missing after install attempt: $command_name"
    done
}

require_root() {
    [ "$EUID" -eq 0 ] || fail "please run as root"
}

require_linux() {
    [ "$(uname -s)" = "Linux" ] || fail "this bootstrap script only supports Linux hosts"
}

require_systemd() {
    command_exists systemctl || fail "systemctl is required"
    if [ ! -d /run/systemd/system ]; then
        fail "this bundle expects a systemd host"
    fi
}

resolve_bundle_dir() {
    local input="$1"

    if [ -n "$input" ]; then
        if [ -d "$input" ]; then
            BUNDLE_DIR="$(cd "$input" && pwd)"
            return 0
        fi
        if [ -f "$input" ]; then
            extract_bundle_tarball "$input"
            return 0
        fi
        fail "bundle input does not exist: $input"
    fi

    if [ -f "$SCRIPT_DIR/install-worker-bundle.sh" ] && [ -f "$SCRIPT_DIR/bin/agentd" ]; then
        BUNDLE_DIR="$SCRIPT_DIR"
        return 0
    fi

    if [ -f "$PWD/install-worker-bundle.sh" ] && [ -f "$PWD/bin/agentd" ]; then
        BUNDLE_DIR="$PWD"
        return 0
    fi

    fail "could not locate an extracted agent bundle; pass the bundle tarball path or run from the extracted bundle directory"
}

verify_checksum_file() {
    local bundle_file="$1"
    local checksum_file="$2"
    local expected actual
    [ -f "$checksum_file" ] || fail "checksum file not found: $checksum_file"
    expected="$(awk '{print $1; exit}' "$checksum_file")"
    [ -n "$expected" ] || fail "failed to parse checksum file: $checksum_file"
    actual="$(sha256sum "$bundle_file" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || fail "checksum mismatch for $bundle_file"
}

extract_bundle_tarball() {
    local bundle_file="$1"
    local checksum_file root_entry

    [ -f "$bundle_file" ] || fail "bundle tarball not found: $bundle_file"

    checksum_file="$CHECKSUM_INPUT"
    if [ -z "$checksum_file" ]; then
        if [ -f "${bundle_file}.sha256" ]; then
            checksum_file="${bundle_file}.sha256"
        elif [ -f "${bundle_file%.tar.gz}.sha256" ]; then
            checksum_file="${bundle_file%.tar.gz}.sha256"
        fi
    fi

    if [ "$SKIP_CHECKSUM" != "true" ]; then
        [ -n "$checksum_file" ] || fail "no checksum file was provided or found next to $bundle_file"
        info "Verifying bundle checksum..."
        verify_checksum_file "$bundle_file" "$checksum_file"
    else
        warn "Skipping checksum verification because SKIP_CHECKSUM=true"
    fi

    EXTRACT_ROOT="$(mktemp -d)"
    info "Extracting bundle into $EXTRACT_ROOT..."
    tar -C "$EXTRACT_ROOT" -xzf "$bundle_file"
    root_entry="$(tar -tf "$bundle_file" | awk -F/ 'NR==1 {print $1}')"
    [ -n "$root_entry" ] || fail "failed to determine extracted bundle root from $bundle_file"
    BUNDLE_DIR="$EXTRACT_ROOT/$root_entry"
    [ -d "$BUNDLE_DIR" ] || fail "expected extracted bundle directory is missing: $BUNDLE_DIR"
}

verify_bundle_layout() {
    local required_paths path
    required_paths=(
        install-worker-bundle.sh
        bin/agentd
        env/runtime.env
        env/runtime.env.template
        systemd/agentd.service
        systemd/agentd-tunnel.service
        tor/bin/tor.real
        extensions/bootstrap-provisioner.py
        extensions/bootstrap-provisioner.json
        extensions/portscan-adapter.py
        extensions/portscan-adapter.json
    )
    for path in "${required_paths[@]}"; do
        [ -e "$BUNDLE_DIR/$path" ] || fail "bundle is missing required path: $path"
    done
}

verify_host_architecture() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) ;;
        *)
            fail "this bundle is currently packaged for linux/x86_64 hosts; detected host architecture: $machine"
            ;;
    esac
}

install_runtime_lib_packages() {
    local manager="$1"
    shift
    [ "$#" -gt 0 ] || return 0

    case "$manager" in
        apt)
            install_packages "$manager" "$@"
            ;;
        dnf|yum|pacman|zypper)
            install_packages "$manager" "$@"
            ;;
        *)
            ;;
    esac
}

maybe_fix_missing_libs() {
    local manager="$1"
    shift
    local missing_libs=("$@")
    local packages=() lib
    for lib in "${missing_libs[@]}"; do
        case "$manager" in
            apt)
                case "$lib" in
                    libgcc_s.so.1) packages+=("libgcc-s1") ;;
                esac
                ;;
            dnf|yum)
                case "$lib" in
                    libgcc_s.so.1) packages+=("libgcc") ;;
                esac
                ;;
            pacman)
                case "$lib" in
                    libgcc_s.so.1) packages+=("gcc-libs") ;;
                esac
                ;;
            zypper)
                case "$lib" in
                    libgcc_s.so.1) packages+=("libgcc_s1") ;;
                esac
                ;;
        esac
    done

    if [ "${#packages[@]}" -gt 0 ]; then
        install_runtime_lib_packages "$manager" "${packages[@]}"
    fi
}

check_binary_linkage() {
    local binary="$1"
    local description="$2"
    local output missing
    output="$(ldd "$binary" 2>&1 || true)"
    if printf '%s\n' "$output" | grep -q "not a dynamic executable"; then
        return 0
    fi
    if printf '%s\n' "$output" | grep -Eq "not found|No such file|Error loading shared library"; then
        missing=($(printf '%s\n' "$output" | awk '/not found/ {print $1} /Error loading shared library/ {print $5}'))
        maybe_fix_missing_libs "$(detect_package_manager)" "${missing[@]:-}"
        output="$(ldd "$binary" 2>&1 || true)"
        if printf '%s\n' "$output" | grep -Eq "not found|No such file|Error loading shared library"; then
            fail "$description is missing runtime libraries on this host:\n$output"
        fi
    fi
}

verify_binary_runtime() {
    check_binary_linkage "$BUNDLE_DIR/bin/agentd" "agent binary"
    if [ -f "$BUNDLE_DIR/bin/scanner" ]; then
        check_binary_linkage "$BUNDLE_DIR/bin/scanner" "scanner binary"
    fi
}

run_installer() {
    info "Running bundled installer..."
    if [ "$SKIP_START" = "true" ]; then
        (cd "$BUNDLE_DIR" && AUTO_ENABLE_SERVICES=false ./install-worker-bundle.sh)
    else
        (cd "$BUNDLE_DIR" && ./install-worker-bundle.sh)
    fi
}

wait_for_service_active() {
    local service_name="$1"
    local timeout_seconds="$2"
    local started_at
    started_at="$(date +%s)"
    while true; do
        if systemctl is-active --quiet "$service_name"; then
            return 0
        fi
        if [ $(( $(date +%s) - started_at )) -ge "$timeout_seconds" ]; then
            return 1
        fi
        sleep 2
    done
}

wait_for_agent_token() {
    local state_file="$1"
    local timeout_seconds="$2"
    local started_at
    started_at="$(date +%s)"
    while true; do
        if [ -f "$state_file" ] && grep -q '^AGENT_TOKEN=' "$state_file"; then
            return 0
        fi
        if [ $(( $(date +%s) - started_at )) -ge "$timeout_seconds" ]; then
            return 1
        fi
        sleep 2
    done
}

load_runtime_env_value() {
    local key="$1"
    local file="$2"
    [ -f "$file" ] || return 1
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

verify_control_connectivity() {
    local runtime_env_file="$1"
    local control_url control_proxy http_code
    control_url="$(load_runtime_env_value "CONTROL_URL" "$runtime_env_file" || true)"
    control_proxy="$(load_runtime_env_value "CONTROL_PROXY_URL" "$runtime_env_file" || true)"

    [ -n "$control_url" ] || return 0
    case "$control_url" in
        *".onion"*|*".onion/"*)
            [ -n "$control_proxy" ] || fail "CONTROL_PROXY_URL is required for onion connectivity checks"
            ss -lnt | grep -q ':9050 ' || fail "the bundled Tor proxy is not listening on 127.0.0.1:9050"
            http_code="$(
                curl -sS -o /dev/null -w '%{http_code}' \
                    --max-time 45 \
                    --proxy "$control_proxy" \
                    "$control_url" || true
            )"
            [ "$http_code" != "000" ] || fail "failed to reach the onion control URL through the bundled Tor proxy"
            ;;
    esac
}

show_failure_logs() {
    warn "Recent service logs:"
    journalctl -u agentd-tunnel.service -u agentd.service -n 120 --no-pager || true
}

start_and_verify_services() {
    local runtime_env_file="/etc/agentd/runtime.env"
    local state_env_file="/var/lib/agentd/agent.env"
    local control_url=""

    info "Enabling and starting agentd.service..."
    systemctl enable --now agentd.service

    control_url="$(load_runtime_env_value "CONTROL_URL" "$runtime_env_file" || true)"
    if printf '%s' "$control_url" | grep -q '.onion'; then
        wait_for_service_active "agentd-tunnel.service" "$TOR_SERVICE_WAIT_SECONDS" || {
            show_failure_logs
            fail "agentd-tunnel.service did not become active in time"
        }
    fi

    wait_for_service_active "agentd.service" "$AGENT_SERVICE_WAIT_SECONDS" || {
        show_failure_logs
        fail "agentd.service did not become active in time"
    }

    wait_for_agent_token "$state_env_file" "$AGENT_TOKEN_WAIT_SECONDS" || {
        show_failure_logs
        fail "the agent did not persist an AGENT_TOKEN within the expected time window; if Tor is still bootstrapping, the agent may still be retrying"
    }

    verify_control_connectivity "$runtime_env_file"
}

cleanup() {
    if [ -n "$EXTRACT_ROOT" ] && [ -d "$EXTRACT_ROOT" ] && [ "$KEEP_EXTRACTED" != "true" ]; then
        rm -rf "$EXTRACT_ROOT"
    fi
}

main() {
    print_banner

    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        usage
        exit 0
    fi

    trap cleanup EXIT

    require_root
    require_linux
    ensure_host_prereqs
    require_systemd
    verify_host_architecture
    resolve_bundle_dir "$BUNDLE_INPUT"
    verify_bundle_layout
    verify_binary_runtime
    run_installer

    if [ "$SKIP_START" = "true" ]; then
        warn "Skipping service enable/start because SKIP_START=true"
        exit 0
    fi

    start_and_verify_services

    printf '\nBootstrap complete.\n\n'
    printf 'Installed services:\n'
    printf '  agentd.service\n'
    printf '  agentd-tunnel.service\n'
    printf '\nKey paths:\n'
    printf '  runtime env: /etc/agentd/runtime.env\n'
    printf '  agent state: /var/lib/agentd/agent.env\n'
    printf '  install root: /opt/agentd\n'
    printf '\nStatus:\n'
    systemctl --no-pager --full status agentd.service agentd-tunnel.service || true
}

main "$@"
