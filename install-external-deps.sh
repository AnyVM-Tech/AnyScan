#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_ENV_FILE="${ANYSCAN_RUNTIME_ENV_FILE:-/etc/anyscan/runtime.env}"
RUNTIME_ENV_DIR="$(dirname "$RUNTIME_ENV_FILE")"
LOCAL_ENV_FILE="$SCRIPT_DIR/.external-runtime.env"
LOCAL_BOOTSTRAP_ARTIFACT_DIR="${ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR:-$REPO_ROOT/.cache/anyscan/bootstrap-artifacts}"

# The scanner C source lives in AnyVM-Tech/anyscan-engine-c — a fork of the
# upstream Lorikazzzz/VulnScanner-zmap-alternative- repo that AnyVM-Tech can
# carry patches against (AF_XDP integration, PF_RING ZC dispatch fix, etc.).
# See plans/2026-04-27-portscan-afxdp-plan-v1.md §9.1.
VULNSCANNER_REPO_URL="${ANYSCAN_VULNSCANNER_REPO_URL:-https://github.com/AnyVM-Tech/anyscan-engine-c.git}"
VULNSCANNER_REPO_DIR="${ANYSCAN_VULNSCANNER_REPO_DIR:-$REPO_ROOT/anyscan-engine-c}"
VULNSCANNER_BIN_PATH="$VULNSCANNER_REPO_DIR/scanner"
VULNSCANNER_INSTALLED_BIN="/opt/anyscan/bin/scanner"

# Build-time AF_XDP opt-in. Default 0 keeps every existing AMI building the
# same legacy binary; setting 1 causes every `make` invocation in this
# script (and the bundle/deploy scripts that reuse this output) to pass
# `USE_AF_XDP=1` so the scanner gets the AF_XDP code path linked. The
# anygpt-42 wire-up gap was that nothing in this chain forwarded the flag,
# so the runtime --io-engine=af_xdp knob had no AF_XDP code to dispatch
# to. See plans/2026-04-27-portscan-afxdp-plan-v1.md §3.6.
ANYSCAN_USE_AF_XDP="${ANYSCAN_USE_AF_XDP:-0}"

# True when the existing scanner binary was linked against libxdp at build
# time. The AF_XDP build path (USE_AF_XDP=1 in the engine Makefile) adds
# `-lxdp -lbpf -lelf -lz` so libxdp.so shows up as a dynamic dependency;
# the legacy AF_PACKET-only build does not. We probe ldd first and fall
# back to readelf -d so the check works on hosts that strip glibc.
binary_has_afxdp_linkage() {
	local bin="$1"
	[ -x "$bin" ] || return 1
	if command -v ldd >/dev/null 2>&1; then
		if ldd "$bin" 2>/dev/null | grep -q 'libxdp\.so'; then
			return 0
		fi
	fi
	if command -v readelf >/dev/null 2>&1; then
		if readelf -d "$bin" 2>/dev/null | grep -E '\(NEEDED\)' | grep -q 'libxdp\.so'; then
			return 0
		fi
	fi
	return 1
}

# Resolve the make argv once so install/bundle/deploy paths produce
# byte-identical invocations and the unit test in
# tools/test-install-external-deps-afxdp.sh can assert the expected
# token list. Stays empty (no extra args) when ANYSCAN_USE_AF_XDP=0.
vulnscanner_make_args() {
	if [ "${ANYSCAN_USE_AF_XDP:-0}" = "1" ]; then
		printf 'USE_AF_XDP=1\n'
	fi
}

EXTENSION_MANIFESTS="$SCRIPT_DIR/local-bootstrap-provisioner.json,$SCRIPT_DIR/vulnscanner-zmap-adapter.json"
ANYGPT_API_ENV_FILE_DEFAULT="$REPO_ROOT/apps/api/.env"

print_banner() {
	printf '═══════════════════════════════════════════════════════════\n'
	printf '        AnyScan External Repository Setup Script         \n'
	printf '═══════════════════════════════════════════════════════════\n'
}

# Install build-time dependencies for the AF_XDP I/O path the scanner gains
# in Phase 2 of plans/2026-04-27-portscan-afxdp-plan-v1.md (§4.1). The fork
# Makefile only pulls these in when invoked with `make USE_AF_XDP=1`; with
# the default `make` they are unused, so we make the install best-effort:
# run only when apt-get is available AND we have permission to install
# packages, skip otherwise with a one-line note. The scanner build still
# succeeds without these packages — `make USE_AF_XDP=1` would fail
# loudly later, which is the right escalation.
#
# Set ANYSCAN_INSTALL_AFXDP_DEPS=false to suppress this block (e.g. on
# AMIs where the operator pre-pinned a different libxdp version).
install_afxdp_build_deps() {
	if [ "${ANYSCAN_INSTALL_AFXDP_DEPS:-true}" != "true" ]; then
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf '[*] Skipping AF_XDP build deps: apt-get not on PATH (non-Debian host).\n'
		return 0
	fi
	local apt_cmd=()
	if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
		apt_cmd=(apt-get)
	elif command -v sudo >/dev/null 2>&1; then
		apt_cmd=(sudo -n apt-get)
	else
		printf '[*] Skipping AF_XDP build deps: not root and sudo is not available.\n'
		printf '    Install manually if you plan to build the scanner with USE_AF_XDP=1:\n'
		printf '      sudo apt-get install -y libxdp-dev libbpf-dev libelf-dev\n'
		return 0
	fi
	# Probe sudo non-interactively; if it would prompt, bail rather than
	# block the script in CI.
	if [ "${apt_cmd[0]}" = "sudo" ] && ! sudo -n true >/dev/null 2>&1; then
		printf '[*] Skipping AF_XDP build deps: sudo would prompt for a password.\n'
		printf '    Install manually if you plan to build the scanner with USE_AF_XDP=1:\n'
		printf '      sudo apt-get install -y libxdp-dev libbpf-dev libelf-dev\n'
		return 0
	fi
	printf '[*] Installing AF_XDP build deps (libxdp-dev libbpf-dev libelf-dev)...\n'
	if ! "${apt_cmd[@]}" install -y --no-install-recommends \
		libxdp-dev libbpf-dev libelf-dev >/dev/null; then
		printf '[!] apt-get install of AF_XDP build deps failed; the scanner will still build with default `make`.\n' >&2
		printf '    Re-run with USE_AF_XDP=1 only after libxdp-dev / libbpf-dev / libelf-dev are present.\n' >&2
		return 0
	fi
}

upsert_env_value() {
	local key="$1"
	local value="$2"
	local file="$3"
	python3 - <<'PY' "$file" "$key" "$value"
from pathlib import Path
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
needle = f"{key}="
lines = path.read_text().splitlines() if path.exists() else []
for index, line in enumerate(lines):
    if line.startswith(needle):
        lines[index] = f"{needle}{value}"
        break
else:
    lines.append(f"{needle}{value}")
path.write_text("\n".join(lines) + "\n")
PY
}

print_banner

if ! command -v git >/dev/null 2>&1; then
	printf '[!] git was not found in PATH.\n' >&2
	exit 1
fi

install_afxdp_build_deps

if [ -d "$VULNSCANNER_REPO_DIR/.git" ]; then
	printf '[*] Updating external repository in %s...\n' "$VULNSCANNER_REPO_DIR"
	git -C "$VULNSCANNER_REPO_DIR" fetch --tags --prune
	git -C "$VULNSCANNER_REPO_DIR" pull --ff-only
else
	printf '[*] Cloning %s into %s...\n' "$VULNSCANNER_REPO_URL" "$VULNSCANNER_REPO_DIR"
	git clone "$VULNSCANNER_REPO_URL" "$VULNSCANNER_REPO_DIR"
fi

need_build=0
if [ ! -x "$VULNSCANNER_BIN_PATH" ]; then
	need_build=1
elif [ "$ANYSCAN_USE_AF_XDP" = "1" ] && ! binary_has_afxdp_linkage "$VULNSCANNER_BIN_PATH"; then
	# Cached binary was built with the legacy USE_AF_XDP=0 path. The
	# AF_XDP code is not linked in, so leaving this in place silently
	# defeats `--io-engine=af_xdp`. Force a clean rebuild rather than
	# an incremental one — partial artifacts from the previous build
	# can mask missing source files added by the AF_XDP block of the
	# engine Makefile.
	printf '[*] Existing scanner at %s lacks libxdp linkage; forcing rebuild because ANYSCAN_USE_AF_XDP=1.\n' "$VULNSCANNER_BIN_PATH"
	if [ -f "$VULNSCANNER_REPO_DIR/Makefile" ] && command -v make >/dev/null 2>&1; then
		make -C "$VULNSCANNER_REPO_DIR" clean >/dev/null 2>&1 || true
	fi
	rm -f "$VULNSCANNER_BIN_PATH"
	need_build=1
fi

if [ "$need_build" = "1" ]; then
	if [ -f "$VULNSCANNER_REPO_DIR/Makefile" ] && command -v make >/dev/null 2>&1; then
		# shellcheck disable=SC2046  # word-splitting wanted: function emits 0 or 1 token
		make_args=( $(vulnscanner_make_args) )
		if [ "${#make_args[@]}" -gt 0 ]; then
			printf '[*] Building VulnScanner scanner binary with %s...\n' "${make_args[*]}"
		else
			printf '[*] Building VulnScanner scanner binary...\n'
		fi
		make -C "$VULNSCANNER_REPO_DIR" "${make_args[@]}"
	else
		printf '[!] Scanner binary is missing and make is unavailable.\n' >&2
		exit 1
	fi
fi

if [ ! -x "$VULNSCANNER_BIN_PATH" ]; then
	printf '[!] Expected scanner binary was not created at %s\n' "$VULNSCANNER_BIN_PATH" >&2
	exit 1
fi

if [ "$ANYSCAN_USE_AF_XDP" = "1" ] && ! binary_has_afxdp_linkage "$VULNSCANNER_BIN_PATH"; then
	printf '[!] ANYSCAN_USE_AF_XDP=1 but %s does not link libxdp.so. Build deps were probably missing — install libxdp-dev/libbpf-dev/libelf-dev and re-run.\n' \
		"$VULNSCANNER_BIN_PATH" >&2
	exit 1
fi

mkdir -p "$(dirname "$LOCAL_ENV_FILE")" "$LOCAL_BOOTSTRAP_ARTIFACT_DIR"
printf '[*] Writing repo-local AnyScan env snippet to %s...\n' "$LOCAL_ENV_FILE"
touch "$LOCAL_ENV_FILE"
upsert_env_value "ANYSCAN_EXTENSION_MANIFEST_PATHS" "$EXTENSION_MANIFESTS" "$LOCAL_ENV_FILE"
upsert_env_value "ANYSCAN_VULNSCANNER_BIN" "$VULNSCANNER_BIN_PATH" "$LOCAL_ENV_FILE"
upsert_env_value "ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR" "$LOCAL_BOOTSTRAP_ARTIFACT_DIR" "$LOCAL_ENV_FILE"

if [ -f "$ANYGPT_API_ENV_FILE_DEFAULT" ]; then
	upsert_env_value "ANYSCAN_ANYGPT_API_ENV_FILE" "$ANYGPT_API_ENV_FILE_DEFAULT" "$LOCAL_ENV_FILE"
fi

if [ -d /opt/anyscan/bin ] && [ -w /opt/anyscan/bin ]; then
	printf '[*] Installing scanner into %s...\n' "$VULNSCANNER_INSTALLED_BIN"
	install -m 0755 "$VULNSCANNER_BIN_PATH" "$VULNSCANNER_INSTALLED_BIN"
fi

if { [ -f "$RUNTIME_ENV_FILE" ] && [ -w "$RUNTIME_ENV_FILE" ]; } || { [ ! -e "$RUNTIME_ENV_FILE" ] && [ -d "$RUNTIME_ENV_DIR" ] && [ -w "$RUNTIME_ENV_DIR" ]; }; then
	printf '[*] Updating runtime env file %s...\n' "$RUNTIME_ENV_FILE"
	touch "$RUNTIME_ENV_FILE"
	upsert_env_value "ANYSCAN_EXTENSION_MANIFEST_PATHS" "$EXTENSION_MANIFESTS" "$RUNTIME_ENV_FILE"
	if [ -x "$VULNSCANNER_INSTALLED_BIN" ]; then
		upsert_env_value "ANYSCAN_VULNSCANNER_BIN" "$VULNSCANNER_INSTALLED_BIN" "$RUNTIME_ENV_FILE"
	else
		upsert_env_value "ANYSCAN_VULNSCANNER_BIN" "$VULNSCANNER_BIN_PATH" "$RUNTIME_ENV_FILE"
	fi
	upsert_env_value "ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR" "$LOCAL_BOOTSTRAP_ARTIFACT_DIR" "$RUNTIME_ENV_FILE"
	upsert_env_value "ANYSCAN_WORKER_SUPPORTS_BOOTSTRAP" "true" "$RUNTIME_ENV_FILE"
	if [ -f "$ANYGPT_API_ENV_FILE_DEFAULT" ]; then
		upsert_env_value "ANYSCAN_ANYGPT_API_ENV_FILE" "$ANYGPT_API_ENV_FILE_DEFAULT" "$RUNTIME_ENV_FILE"
	fi
else
	printf '[*] Skipping runtime env update because %s is not writable.\n' "$RUNTIME_ENV_FILE"
fi

printf '\nSetup complete.\n\n'
printf 'External repository:\n'
printf '  %s\n' "$VULNSCANNER_REPO_DIR"
printf 'Scanner binary:\n'
printf '  %s\n' "$VULNSCANNER_BIN_PATH"
printf 'Repo-local env snippet:\n'
printf '  %s\n' "$LOCAL_ENV_FILE"
printf '\nYou can source the env snippet for local runs:\n'
printf '  set -a && source %s && set +a\n' "$LOCAL_ENV_FILE"
if [ -f "$RUNTIME_ENV_FILE" ]; then
	printf '\nIf AnyScan is installed as a service, restart it after setup:\n'
	printf '  systemctl restart anyscan-api anyscan-worker\n'
fi
