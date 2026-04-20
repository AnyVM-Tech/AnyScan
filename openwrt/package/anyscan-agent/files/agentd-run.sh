#!/bin/sh
set -eu

. /lib/functions.sh

CONFIG_NAME="agentd"
CONFIG_SECTION="main"
AGENT_BIN="/usr/sbin/agentd"
STATE_ROOT="/var/lib/agentd"
DEFAULT_STATE_FILE="$STATE_ROOT/agent.env"
DEFAULT_ARTIFACT_DIR="$STATE_ROOT/artifacts"
DEFAULT_CONTROL_URL="http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion"
DEFAULT_CONTROL_PROXY_URL="socks5h://127.0.0.1:9050"
DEFAULT_POLL_INTERVAL_SECONDS="15"
DEFAULT_SCANNER_BIN="/usr/libexec/agentd/scanner"
BOOTSTRAP_MANIFEST="/usr/share/agentd/extensions/bootstrap-provisioner.json"
SCANNER_MANIFEST="/usr/share/agentd/extensions/portscan-adapter.json"
BUNDLED_MANIFEST_DIR="/usr/share/agentd/extensions/bundled/manifests"
RUNTIME_ENV_FILE="/var/run/agentd.env"

append_csv_value() {
	local current="$1"
	local next="$2"

	if [ -z "$next" ]; then
		printf '%s' "$current"
	elif [ -z "$current" ]; then
		printf '%s' "$next"
	else
		printf '%s,%s' "$current" "$next"
	fi
}

AGENT_TAGS_CSV=""
collect_agent_tag() {
	local tag="$1"
	[ -n "$tag" ] || return 0
	AGENT_TAGS_CSV="$(append_csv_value "$AGENT_TAGS_CSV" "$tag")"
}

wait_for_tor_proxy() {
	local timeout_seconds="$1"
	local waited="0"

	command -v nc >/dev/null 2>&1 || return 0

	while ! nc -z 127.0.0.1 9050 >/dev/null 2>&1; do
		if [ "$waited" -ge "$timeout_seconds" ]; then
			echo "agentd: Tor SOCKS proxy did not become ready after ${timeout_seconds}s; continuing" >&2
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
}

config_load "$CONFIG_NAME"

local_enabled="0"
config_get_bool local_enabled "$CONFIG_SECTION" enabled 0
[ "$local_enabled" -eq 1 ] || exit 0

control_url=""
control_proxy_url=""
agent_id=""
agent_name=""
agent_pool=""
bootstrap_code=""
artifact_dir=""
state_file=""
scanner_bin=""
scan_interval_seconds=""
tor_wait_timeout=""
allow_invalid_tls="0"
enable_bootstrap="0"
enable_scanner="0"
tor_wait_enabled="1"

config_get control_url "$CONFIG_SECTION" control_url "$DEFAULT_CONTROL_URL"
config_get control_proxy_url "$CONFIG_SECTION" control_proxy_url "$DEFAULT_CONTROL_PROXY_URL"
config_get agent_id "$CONFIG_SECTION" agent_id ""
config_get agent_name "$CONFIG_SECTION" agent_name ""
config_get agent_pool "$CONFIG_SECTION" agent_pool ""
config_get bootstrap_code "$CONFIG_SECTION" bootstrap_code ""
config_get artifact_dir "$CONFIG_SECTION" artifact_dir "$DEFAULT_ARTIFACT_DIR"
config_get state_file "$CONFIG_SECTION" state_file "$DEFAULT_STATE_FILE"
config_get scanner_bin "$CONFIG_SECTION" scanner_bin "$DEFAULT_SCANNER_BIN"
config_get scan_interval_seconds "$CONFIG_SECTION" scan_interval_seconds "$DEFAULT_POLL_INTERVAL_SECONDS"
config_get tor_wait_timeout "$CONFIG_SECTION" tor_wait_timeout "120"
config_get_bool allow_invalid_tls "$CONFIG_SECTION" allow_invalid_tls 0
config_get_bool enable_bootstrap "$CONFIG_SECTION" enable_bootstrap 0
config_get_bool enable_scanner "$CONFIG_SECTION" enable_scanner 0
config_get_bool tor_wait_enabled "$CONFIG_SECTION" tor_wait_enabled 1
config_list_foreach "$CONFIG_SECTION" agent_tag collect_agent_tag

if [ -z "$agent_id" ]; then
	agent_id="$(cat /proc/sys/kernel/hostname 2>/dev/null || echo agentd-opal)"
fi

if [ -z "$agent_name" ]; then
	agent_name="$agent_id"
fi

mkdir -p "$STATE_ROOT" "$(dirname "$state_file")" "$artifact_dir" "$(dirname "$RUNTIME_ENV_FILE")"

if [ -f "$state_file" ]; then
	# shellcheck disable=SC1090
	. "$state_file"
fi

manifest_paths=""
if [ "$enable_bootstrap" -eq 1 ] && [ -f "$BOOTSTRAP_MANIFEST" ]; then
	manifest_paths="$(append_csv_value "$manifest_paths" "$BOOTSTRAP_MANIFEST")"
fi
if [ "$enable_scanner" -eq 1 ] && [ -f "$SCANNER_MANIFEST" ]; then
	manifest_paths="$(append_csv_value "$manifest_paths" "$SCANNER_MANIFEST")"
fi

if [ "$tor_wait_enabled" -eq 1 ]; then
	case "$control_url" in
		*.onion|*.onion/*)
			wait_for_tor_proxy "$tor_wait_timeout"
			;;
	esac
fi

cat >"$RUNTIME_ENV_FILE" <<EOF
CONTROL_URL=$control_url
CONTROL_PROXY_URL=$control_proxy_url
AGENT_ID=$agent_id
AGENT_NAME=$agent_name
AGENT_POOL=$agent_pool
AGENT_TAGS=$AGENT_TAGS_CSV
AGENT_BOOTSTRAP_CODE=$bootstrap_code
AGENT_ENABLE_BOOTSTRAP=$([ "$enable_bootstrap" -eq 1 ] && printf 'true' || printf 'false')
ARTIFACT_DIR=$artifact_dir
AGENT_STATE_FILE=$state_file
POLL_INTERVAL_SECONDS=$scan_interval_seconds
ALLOW_INVALID_TLS=$([ "$allow_invalid_tls" -eq 1 ] && printf 'true' || printf 'false')
SCANNER_BIN=$scanner_bin
EXTENSION_MANIFEST_PATHS=$manifest_paths
EXTENSION_MANIFEST_DIRS=$BUNDLED_MANIFEST_DIR
EOF
chmod 0600 "$RUNTIME_ENV_FILE"

export CONTROL_URL="$control_url"
export CONTROL_PROXY_URL="$control_proxy_url"
export AGENT_ID="$agent_id"
export AGENT_NAME="$agent_name"
export AGENT_POOL="$agent_pool"
export AGENT_TAGS="$AGENT_TAGS_CSV"
export AGENT_ENABLE_BOOTSTRAP="$([ "$enable_bootstrap" -eq 1 ] && printf 'true' || printf 'false')"
export ARTIFACT_DIR="$artifact_dir"
export AGENT_STATE_FILE="$state_file"
export POLL_INTERVAL_SECONDS="$scan_interval_seconds"
export ALLOW_INVALID_TLS="$([ "$allow_invalid_tls" -eq 1 ] && printf 'true' || printf 'false')"
export SCANNER_BIN="$scanner_bin"
export EXTENSION_MANIFEST_DIRS="$BUNDLED_MANIFEST_DIR"

if [ -n "$bootstrap_code" ]; then
	export AGENT_BOOTSTRAP_CODE="$bootstrap_code"
fi
if [ -n "$manifest_paths" ]; then
	export EXTENSION_MANIFEST_PATHS="$manifest_paths"
else
	unset EXTENSION_MANIFEST_PATHS
fi
if [ -n "${AGENT_TOKEN:-}" ]; then
	export AGENT_TOKEN
fi

exec "$AGENT_BIN" daemon
