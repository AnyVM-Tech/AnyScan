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

# Build-time PF_RING ZC opt-in (anygpt-46). Mirrors ANYSCAN_USE_AF_XDP. The
# engine Makefile's USE_PFRING_ZC=1 branch adds -DUSE_PFRING_ZC, links
# `-lpfring -lpcap`, and pulls src/{send,recv}-pfring.c into the build so
# the io_engine_pfring_zc vtable in engine.c is wired into pick_io_engine.
# Without this flag, --io-engine=pfring_zc fails at startup with
# "binary not built with USE_PFRING_ZC=1". The runtime --io-engine knob
# (ANYSCAN_SCANNER_IO_ENGINE) plumbed in PR #70 means nothing if this
# build flag never reaches make.
#
# IMPORTANT (license): PF_RING ZC requires a commercial per-host license
# from ntop to operate at full speed. Without a license, the libpfring
# runtime falls back to a community/demo mode that throttles ZC traffic
# to ~100k pps, which is below the rate AF_PACKET already sustains. Set
# this to 1 only on hosts where the license file is present and the
# pfring kernel module is loaded; see runtime.worker.env.template for
# the runtime-side gating knob ANYSCAN_PFRING_ZC_AVAILABLE.
ANYSCAN_USE_PFRING_ZC="${ANYSCAN_USE_PFRING_ZC:-0}"

# Build-time DPDK opt-in. Mirrors ANYSCAN_USE_AF_XDP / ANYSCAN_USE_PFRING_ZC.
# When 1 the engine make is invoked with `USE_DPDK=1` so the scanner gets
# librte_eal + librte_ethdev + librte_mbuf + librte_net_ena linked in and the
# io_engine_dpdk vtable in src/engine.c is reachable from pick_io_engine().
# Without this flag, --io-engine=dpdk fails at parse time with
# "binary not built with USE_DPDK=1".
#
# DPDK additionally requires HOST setup the apt-get install does NOT cover —
# hugepages reserved + the target NIC bound to vfio-pci. Those are owned by
# tools/setup-dpdk.sh (idempotent + reversible). install-worker-bundle.sh's
# probe_dpdk_runtime_available checks both at runtime so an in-place upgrade
# that flipped USE_DPDK=1 but never ran the host-setup script gets
# ANYSCAN_DPDK_AVAILABLE=false and the adapter falls back to af_packet.
#
# See plans/2026-04-28-portscan-dpdk-impl-v1.md §3.10 for the full wire-up.
ANYSCAN_USE_DPDK="${ANYSCAN_USE_DPDK:-0}"

# Opt-in kernel backport upgrade. Default 0 leaves the running kernel
# untouched (existing AMIs unchanged). Setting 1 installs a Debian
# backports kernel image so the host can run kernel 6.16+ with the
# in-flight `ena_xdp_zc` ENA driver patches that AF_XDP zerocopy on
# ENA needs. The PR 65 §10 / anygpt-42 live bench showed ENA on
# kernel 6.12.74 caps the c6in.metal 8-NIC cap=4 throughput at ~22M
# pps in drv+copy mode, vs the 30-50M projection driver-mode zerocopy
# was supposed to deliver. See PR 65 issuecomment-4336192354 for the
# constraint trace.
#
# The suite and package default to the host's Debian codename:
# trixie-backports / linux-image-amd64 on Debian 13, bookworm-backports
# / linux-image-cloud-amd64 on Debian 12. PR 65 issuecomment-4338158487
# (anygpt-48) caught the previous static bookworm-backports default
# silently no-op'ing on the Trixie AMI: bookworm-backports
# linux-image-cloud-amd64 resolves to 6.12.74-2~bpo12+1 — exactly the
# kernel the metal already runs — so the opt-in completed "0 upgraded,
# 0 newly installed" and the operator got a green light without ever
# upgrading. Trixie's linux-image-cloud-amd64 is also still 6.12 as of
# 2026-04, so we explicitly switch the package to the non-cloud
# linux-image-amd64 on non-bookworm suites.
#
# Operator-set ANYSCAN_KERNEL_BACKPORT_SUITE / _PACKAGE / _SOURCES_LIST
# still win — the codename detection is just a smarter default.
#
# Never auto-reboots. The new kernel is staged on disk and the operator
# has to schedule the reboot themselves. After install the script
# probes `/sys/module/ena/version` + dmesg for `ena_xdp_zc` support
# and warns if absent so the operator knows whether the
# CURRENTLY-RUNNING kernel will deliver zerocopy.

# Detect the Debian codename so backport defaults match the running
# release. /etc/os-release VERSION_CODENAME is the canonical source on
# Debian/Ubuntu hosts; missing or unreadable file → fall back to
# "bookworm" so the legacy default doesn't change for hosts where the
# os-release file isn't accessible. Override the file path with
# ANYSCAN_OS_RELEASE_FILE for testing.
detect_debian_codename() {
	local release_file="${ANYSCAN_OS_RELEASE_FILE:-/etc/os-release}"
	local codename=""
	if [ -r "$release_file" ]; then
		# shellcheck source=/dev/null
		codename="$(. "$release_file" 2>/dev/null && printf '%s\n' "${VERSION_CODENAME:-}")"
	fi
	if [ -z "$codename" ]; then
		codename="bookworm"
	fi
	printf '%s\n' "$codename"
}

ANYSCAN_INSTALL_KERNEL_BACKPORT="${ANYSCAN_INSTALL_KERNEL_BACKPORT:-0}"
ANYSCAN_KERNEL_BACKPORT_MIN_VERSION="${ANYSCAN_KERNEL_BACKPORT_MIN_VERSION:-6.16}"
_anyscan_codename="$(detect_debian_codename)"
ANYSCAN_KERNEL_BACKPORT_SUITE="${ANYSCAN_KERNEL_BACKPORT_SUITE:-${_anyscan_codename}-backports}"
# Package selection: trixie-backports linux-image-cloud-amd64 is still
# 6.12 as of 2026-04 — only the non-cloud linux-image-amd64 jumps to
# 6.19. Bookworm-backports keeps the legacy linux-image-cloud-amd64
# default for back-compat on operators still on bookworm hosts.
if [ "$ANYSCAN_KERNEL_BACKPORT_SUITE" = "bookworm-backports" ]; then
	_anyscan_default_pkg="linux-image-cloud-amd64"
else
	_anyscan_default_pkg="linux-image-amd64"
fi
ANYSCAN_KERNEL_BACKPORT_PACKAGE="${ANYSCAN_KERNEL_BACKPORT_PACKAGE:-$_anyscan_default_pkg}"
ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST="${ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST:-/etc/apt/sources.list.d/anyscan-${ANYSCAN_KERNEL_BACKPORT_SUITE}.list}"
ANYSCAN_KERNEL_BACKPORT_MIRROR="${ANYSCAN_KERNEL_BACKPORT_MIRROR:-http://deb.debian.org/debian}"
unset _anyscan_codename _anyscan_default_pkg

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

# True when the existing scanner binary was linked against libpfring at
# build time. The PF_RING ZC build path (USE_PFRING_ZC=1 in the engine
# Makefile) adds `-lpfring -lpcap` so libpfring.so shows up as a dynamic
# dependency; the legacy build does not link libpfring at all. Same
# ldd → readelf fallback as binary_has_afxdp_linkage so the check works
# on stripped or static glibc hosts.
binary_has_pfring_zc_linkage() {
	local bin="$1"
	[ -x "$bin" ] || return 1
	if command -v ldd >/dev/null 2>&1; then
		if ldd "$bin" 2>/dev/null | grep -q 'libpfring\.so'; then
			return 0
		fi
	fi
	if command -v readelf >/dev/null 2>&1; then
		if readelf -d "$bin" 2>/dev/null | grep -E '\(NEEDED\)' | grep -q 'libpfring\.so'; then
			return 0
		fi
	fi
	return 1
}

# True when the existing scanner binary was linked against librte_eal at
# build time. The DPDK build path (USE_DPDK=1) pulls in libdpdk via
# pkg-config which produces ~50 -lrte_* link flags; we probe for librte_eal
# specifically because every DPDK-built binary links it (it's the EAL core
# library) and PMD-only / mempool-only DPDK applications still need it.
# Same ldd → readelf -d fallback shape as binary_has_afxdp_linkage so the
# check works on hosts that strip glibc.
binary_has_dpdk_linkage() {
	local bin="$1"
	[ -x "$bin" ] || return 1
	if command -v ldd >/dev/null 2>&1; then
		if ldd "$bin" 2>/dev/null | grep -q 'librte_eal\.so'; then
			return 0
		fi
	fi
	if command -v readelf >/dev/null 2>&1; then
		if readelf -d "$bin" 2>/dev/null | grep -E '\(NEEDED\)' | grep -q 'librte_eal\.so'; then
			return 0
		fi
	fi
	return 1
}

# Resolve the make argv once so install/bundle/deploy paths produce
# byte-identical invocations and the unit tests in
# tools/test-install-external-deps-{afxdp,pfring-zc}.sh can assert the
# expected token list. Stays empty (no extra args) when both
# ANYSCAN_USE_AF_XDP and ANYSCAN_USE_PFRING_ZC are 0.
vulnscanner_make_args() {
	if [ "${ANYSCAN_USE_AF_XDP:-0}" = "1" ]; then
		printf 'USE_AF_XDP=1\n'
	fi
	if [ "${ANYSCAN_USE_PFRING_ZC:-0}" = "1" ]; then
		printf 'USE_PFRING_ZC=1\n'
	fi
	if [ "${ANYSCAN_USE_DPDK:-0}" = "1" ]; then
		printf 'USE_DPDK=1\n'
	fi
}

# Lexicographic numeric compare of two `<major>.<minor>` version strings.
# Returns 0 (true) when $1 >= $2. Tolerant of missing fields and
# non-numeric trailing tokens (`6.16.0-rc1` / `6.16+deb13` etc).
kernel_version_at_least() {
	local have="$1" need="$2"
	local have_major have_minor need_major need_minor
	have_major="${have%%.*}"
	have_minor="${have#*.}"
	have_minor="${have_minor%%.*}"
	have_minor="${have_minor%%[!0-9]*}"
	need_major="${need%%.*}"
	need_minor="${need#*.}"
	need_minor="${need_minor%%.*}"
	need_minor="${need_minor%%[!0-9]*}"
	have_major="${have_major:-0}"
	have_minor="${have_minor:-0}"
	need_major="${need_major:-0}"
	need_minor="${need_minor:-0}"
	if [ "$have_major" -gt "$need_major" ]; then
		return 0
	fi
	if [ "$have_major" -lt "$need_major" ]; then
		return 1
	fi
	if [ "$have_minor" -ge "$need_minor" ]; then
		return 0
	fi
	return 1
}

# Probe the ena driver for AF_XDP zerocopy capability. ena_xdp_zc is
# the upstream patch series (in-flight against kernel 6.16+) that lets
# ENA advertise XDP_ZC; without it the scanner's AF_XDP path falls
# back to drv+copy and caps c6in.metal 8-NIC cap=4 throughput at
# ~22M pps (anygpt-42 live bench). Best-effort: a kernel with no
# `/sys/module/ena/version` (ena module not loaded) or no
# ena_xdp_zc indicator in dmesg just emits a warning so the operator
# knows zerocopy is unavailable on the CURRENTLY-RUNNING kernel
# (most useful right after a reboot into the backport kernel).
probe_ena_xdp_zc() {
	if [ ! -e /sys/module/ena/version ]; then
		printf '[!] ena driver not loaded on running kernel — cannot confirm AF_XDP zerocopy support. Reboot into the backport kernel and re-run this probe.\n' >&2
		return 1
	fi
	local ena_ver
	ena_ver="$(cat /sys/module/ena/version 2>/dev/null || true)"
	printf '[*] ena driver version on running kernel: %s\n' "${ena_ver:-unknown}"
	if command -v dmesg >/dev/null 2>&1 \
		&& dmesg 2>/dev/null | grep -qiE 'ena_xdp_zc|ena.*xdp.*zerocopy|ena.*xdp_zc'; then
		printf '[*] ena_xdp_zc indicator detected in dmesg — AF_XDP zerocopy should be available.\n'
		return 0
	fi
	printf '[!] ena_xdp_zc indicator NOT found in dmesg on running kernel %s. AF_XDP zerocopy may not be available; the scanner will fall back to drv+copy mode. Reboot into kernel %s+ and re-run if you just installed the backport image.\n' \
		"$(uname -r 2>/dev/null || echo unknown)" "$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION" >&2
	return 1
}

# Opt-in path that installs a backport kernel image (default
# linux-image-cloud-amd64 from Debian bookworm-backports) on hosts
# whose stock kernel is older than 6.16. Default OFF — existing
# AMIs are unchanged. Never auto-reboots: installing a kernel image
# only stages it on disk, the operator has to schedule the reboot
# themselves. After the install (or if the kernel is already new
# enough) probes /sys/module/ena/version + dmesg for ena_xdp_zc
# support and warns if absent.
install_kernel_backport_if_requested() {
	if [ "${ANYSCAN_INSTALL_KERNEL_BACKPORT:-0}" != "1" ]; then
		return 0
	fi
	local current_kernel current_kernel_ver
	current_kernel="$(uname -r 2>/dev/null || echo unknown)"
	current_kernel_ver="${current_kernel%%-*}"
	printf '[*] ANYSCAN_INSTALL_KERNEL_BACKPORT=1 — current kernel %s (need >= %s for ena_xdp_zc).\n' \
		"$current_kernel" "$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION"
	if kernel_version_at_least "$current_kernel_ver" "$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION"; then
		printf '[*] Running kernel already meets %s+; backport image install skipped.\n' \
			"$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION"
		probe_ena_xdp_zc || true
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf '[*] Skipping kernel backport: apt-get not on PATH (this knob targets Debian-family hosts).\n'
		return 0
	fi
	local apt_cmd=() tee_cmd=()
	if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
		apt_cmd=(apt-get)
		tee_cmd=(tee)
	elif command -v sudo >/dev/null 2>&1; then
		if ! sudo -n true >/dev/null 2>&1; then
			printf '[*] Skipping kernel backport: sudo would prompt for a password.\n'
			printf '    Install manually if you want kernel %s+:\n' "$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION"
			printf '      echo "deb %s %s main" | sudo tee %s\n' \
				"$ANYSCAN_KERNEL_BACKPORT_MIRROR" \
				"$ANYSCAN_KERNEL_BACKPORT_SUITE" \
				"$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST"
			printf '      sudo apt-get update && sudo apt-get install -y -t %s %s\n' \
				"$ANYSCAN_KERNEL_BACKPORT_SUITE" "$ANYSCAN_KERNEL_BACKPORT_PACKAGE"
			return 0
		fi
		apt_cmd=(sudo -n apt-get)
		tee_cmd=(sudo -n tee)
	else
		printf '[*] Skipping kernel backport: not root and sudo is not available.\n'
		return 0
	fi
	if [ ! -f "$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST" ]; then
		printf '[*] Writing apt source for %s to %s...\n' \
			"$ANYSCAN_KERNEL_BACKPORT_SUITE" "$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST"
		if ! printf 'deb %s %s main\n' \
				"$ANYSCAN_KERNEL_BACKPORT_MIRROR" \
				"$ANYSCAN_KERNEL_BACKPORT_SUITE" \
			| "${tee_cmd[@]}" "$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST" >/dev/null; then
			printf '[!] Failed to write %s; cannot install backport kernel image. Skipping.\n' \
				"$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST" >&2
			return 0
		fi
	else
		printf '[*] Reusing existing apt source list at %s.\n' "$ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST"
	fi
	printf '[*] Refreshing apt indexes for %s...\n' "$ANYSCAN_KERNEL_BACKPORT_SUITE"
	if ! "${apt_cmd[@]}" update >/dev/null 2>&1; then
		printf '[!] apt-get update failed; cannot install backport kernel image. Skipping.\n' >&2
		return 0
	fi
	printf '[*] Installing %s from %s (no auto-reboot)...\n' \
		"$ANYSCAN_KERNEL_BACKPORT_PACKAGE" "$ANYSCAN_KERNEL_BACKPORT_SUITE"
	if ! "${apt_cmd[@]}" install -y --no-install-recommends \
			-t "$ANYSCAN_KERNEL_BACKPORT_SUITE" \
			"$ANYSCAN_KERNEL_BACKPORT_PACKAGE" >/dev/null 2>&1; then
		printf '[!] Failed to install %s from %s; existing kernel unchanged.\n' \
			"$ANYSCAN_KERNEL_BACKPORT_PACKAGE" "$ANYSCAN_KERNEL_BACKPORT_SUITE" >&2
		return 0
	fi
	printf '[*] REBOOT REQUIRED: backport kernel image %s staged on disk. This script does NOT auto-reboot — schedule a maintenance window and reboot to activate kernel %s+.\n' \
		"$ANYSCAN_KERNEL_BACKPORT_PACKAGE" "$ANYSCAN_KERNEL_BACKPORT_MIN_VERSION"
	probe_ena_xdp_zc || true
	return 0
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

# Install build-time dependencies for the PF_RING ZC I/O path the scanner
# Makefile gains under USE_PFRING_ZC=1 (-lpfring -lpcap). libpfring is not
# in stock Debian/Ubuntu, so this helper attempts the system apt-get path
# first (some derivatives carry it) and falls back to a clear pointer to
# the ntop apt repo (https://packages.ntop.org/apt-stable/) when the
# package is not available. We intentionally do NOT auto-add a
# third-party apt repo from this script — that would alter package
# provenance on every CI host that runs install-external-deps.sh.
# Operators who want PF_RING ZC are expected to provision the ntop repo
# at AMI/image-build time (or by hand) before flipping
# ANYSCAN_USE_PFRING_ZC=1.
#
# Same fail-open semantics as install_afxdp_build_deps: skip if apt-get
# missing, skip if no privilege, skip if sudo would prompt. The build
# fails loudly later if libpfring-dev was not installable — that is the
# correct escalation rather than masking the missing dep.
#
# Set ANYSCAN_INSTALL_PFRING_ZC_DEPS=false to suppress this block.
install_pfring_zc_build_deps() {
	if [ "${ANYSCAN_INSTALL_PFRING_ZC_DEPS:-true}" != "true" ]; then
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf '[*] Skipping PF_RING ZC build deps: apt-get not on PATH (non-Debian host).\n'
		return 0
	fi
	local apt_cmd=()
	if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
		apt_cmd=(apt-get)
	elif command -v sudo >/dev/null 2>&1; then
		apt_cmd=(sudo -n apt-get)
	else
		printf '[*] Skipping PF_RING ZC build deps: not root and sudo is not available.\n'
		printf '    Install manually if you plan to build the scanner with USE_PFRING_ZC=1:\n'
		printf '      # Add the ntop apt repo (one-time per AMI):\n'
		printf '      #   wget https://packages.ntop.org/apt-stable/<distro>/all/apt-ntop-stable.deb\n'
		printf '      #   sudo dpkg -i apt-ntop-stable.deb && sudo apt-get update\n'
		printf '      sudo apt-get install -y libpfring-dev pfring-dkms\n'
		return 0
	fi
	if [ "${apt_cmd[0]}" = "sudo" ] && ! sudo -n true >/dev/null 2>&1; then
		printf '[*] Skipping PF_RING ZC build deps: sudo would prompt for a password.\n'
		printf '    Install manually if you plan to build the scanner with USE_PFRING_ZC=1:\n'
		printf '      sudo apt-get install -y libpfring-dev pfring-dkms\n'
		return 0
	fi
	printf '[*] Installing PF_RING ZC build deps (libpfring-dev pfring-dkms)...\n'
	if ! "${apt_cmd[@]}" install -y --no-install-recommends \
		libpfring-dev pfring-dkms >/dev/null 2>&1; then
		printf '[!] apt-get install of PF_RING build deps failed.\n' >&2
		printf '    libpfring-dev / pfring-dkms are not in stock Debian/Ubuntu repos. Provision the ntop apt-stable repo (https://packages.ntop.org/apt-stable/) and re-run, or install via dkms manually.\n' >&2
		printf '    The default `make` will still succeed — only `make USE_PFRING_ZC=1` requires these packages.\n' >&2
		return 0
	fi
}

# Install build-time dependencies for the DPDK I/O path the scanner gains
# under USE_DPDK=1 in the engine Makefile (-lrte_eal -lrte_ethdev -lrte_mbuf
# etc, pulled in via `pkg-config --libs libdpdk`). libdpdk-dev is in main on
# Debian bookworm/trixie + Ubuntu 24.04 noble. Same fail-open semantics as
# install_afxdp_build_deps: skip if apt-get missing, skip if no privilege,
# skip if sudo would prompt. The default `make` does not need these
# packages — only `make USE_DPDK=1` does — so failure to install just
# means USE_DPDK=1 builds will fail loudly later, which is the correct
# escalation rather than silently producing a non-DPDK binary.
#
# DPDK additionally requires HOST setup (hugepages + vfio-pci binding)
# that this function does NOT do — that lives in tools/setup-dpdk.sh and
# is the install-time, not build-time, prerequisite. The split exists
# because hugepages reservation modifies system memory pressure and
# binding NICs to vfio-pci removes them from kernel networking; both
# need an explicit operator action, not an apt-get side-effect.
#
# Set ANYSCAN_INSTALL_DPDK_DEPS=false to suppress this block (e.g. on
# AMIs where the operator pre-pinned a different libdpdk version).
# Per-NIC DPDK PMD packages. Debian DPDK 24.11.x ships every Poll-Mode
# Driver as its own package (librte-net-<vendor><abi>) instead of shoving
# them all into libdpdk-dev. Without the relevant PMD installed,
# rte_eal_init() succeeds but no eth ports are probed and the scanner
# refuses to start (anygpt-52 hit this on c6in.metal: ENA NICs silently
# absent from rte_eth_dev_count_avail() until librte-net-ena25 was
# apt-installed manually).
#
# We pull both the AWS PMD (ENA — every c6in/c5n/m5n/m6in instance) and
# the Mellanox PMD (mlx5 — bare-metal hosts at Equinix/OVH/Hetzner with
# CX-5/CX-6 NICs). Stock Intel ixgbe/i40e drivers are still in
# libdpdk-dev's auto-pull set so we don't need to name them. The 25 ABI
# suffix matches Debian trixie's DPDK 24.11.x (libdpdk-dev → librte-*-25).
DPDK_PMD_PACKAGES=(librte-net-ena25 librte-net-mlx5-25)

install_dpdk_build_deps() {
	if [ "${ANYSCAN_INSTALL_DPDK_DEPS:-true}" != "true" ]; then
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		printf '[*] Skipping DPDK build deps: apt-get not on PATH (non-Debian host).\n'
		return 0
	fi
	local apt_cmd=()
	if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
		apt_cmd=(apt-get)
	elif command -v sudo >/dev/null 2>&1; then
		apt_cmd=(sudo -n apt-get)
	else
		printf '[*] Skipping DPDK build deps: not root and sudo is not available.\n'
		printf '    Install manually if you plan to build the scanner with USE_DPDK=1:\n'
		printf '      sudo apt-get install -y libdpdk-dev dpdk %s\n' "${DPDK_PMD_PACKAGES[*]}"
		return 0
	fi
	if [ "${apt_cmd[0]}" = "sudo" ] && ! sudo -n true >/dev/null 2>&1; then
		printf '[*] Skipping DPDK build deps: sudo would prompt for a password.\n'
		printf '    Install manually if you plan to build the scanner with USE_DPDK=1:\n'
		printf '      sudo apt-get install -y libdpdk-dev dpdk %s\n' "${DPDK_PMD_PACKAGES[*]}"
		return 0
	fi
	printf '[*] Installing DPDK build deps (libdpdk-dev dpdk %s)...\n' "${DPDK_PMD_PACKAGES[*]}"
	if ! "${apt_cmd[@]}" install -y --no-install-recommends \
		libdpdk-dev dpdk "${DPDK_PMD_PACKAGES[@]}" >/dev/null 2>&1; then
		# Fall back to libdpdk-dev alone if PMD packages are unavailable
		# in the current archive — better to ship a partial DPDK build
		# than fail the whole install. The scanner will still link
		# against librte_eal but rte_eth_dev_count_avail() will return
		# 0 on hosts whose NIC PMD is missing.
		printf '[!] apt-get install of DPDK build deps incl. PMDs failed; retrying without PMDs.\n' >&2
		if ! "${apt_cmd[@]}" install -y --no-install-recommends \
			libdpdk-dev dpdk >/dev/null 2>&1; then
			printf '[!] apt-get install of DPDK build deps failed; the scanner will still build with default `make`.\n' >&2
			printf '    Re-run with USE_DPDK=1 only after libdpdk-dev is present.\n' >&2
			return 0
		fi
		printf '[!] DPDK PMD packages (%s) not installed; rte_eth_dev_count_avail() may return 0 at runtime on ENA/mlx5 hosts.\n' "${DPDK_PMD_PACKAGES[*]}" >&2
		printf '    Install manually once available: sudo apt-get install -y %s\n' "${DPDK_PMD_PACKAGES[*]}" >&2
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
install_pfring_zc_build_deps
install_dpdk_build_deps
install_kernel_backport_if_requested

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
elif [ "$ANYSCAN_USE_PFRING_ZC" = "1" ] && ! binary_has_pfring_zc_linkage "$VULNSCANNER_BIN_PATH"; then
	# Same shape as the AF_XDP cache check: force clean rebuild when
	# the cached binary lacks libpfring linkage. Without this the cache
	# short-circuit at line above would keep shipping the legacy binary
	# and --io-engine=pfring_zc would error at startup.
	printf '[*] Existing scanner at %s lacks libpfring linkage; forcing rebuild because ANYSCAN_USE_PFRING_ZC=1.\n' "$VULNSCANNER_BIN_PATH"
	if [ -f "$VULNSCANNER_REPO_DIR/Makefile" ] && command -v make >/dev/null 2>&1; then
		make -C "$VULNSCANNER_REPO_DIR" clean >/dev/null 2>&1 || true
	fi
	rm -f "$VULNSCANNER_BIN_PATH"
	need_build=1
elif [ "$ANYSCAN_USE_DPDK" = "1" ] && ! binary_has_dpdk_linkage "$VULNSCANNER_BIN_PATH"; then
	# Same shape as the AF_XDP / PF_RING cache checks: force clean
	# rebuild when the cached binary lacks librte_eal linkage. Without
	# this the cache short-circuit above would keep shipping a non-DPDK
	# binary and --io-engine=dpdk would error at parse time with
	# "binary not built with USE_DPDK=1".
	printf '[*] Existing scanner at %s lacks librte_eal linkage; forcing rebuild because ANYSCAN_USE_DPDK=1.\n' "$VULNSCANNER_BIN_PATH"
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

if [ "$ANYSCAN_USE_PFRING_ZC" = "1" ] && ! binary_has_pfring_zc_linkage "$VULNSCANNER_BIN_PATH"; then
	printf '[!] ANYSCAN_USE_PFRING_ZC=1 but %s does not link libpfring.so. Build deps were probably missing — install libpfring-dev (ntop apt-stable repo) and re-run.\n' \
		"$VULNSCANNER_BIN_PATH" >&2
	exit 1
fi

if [ "$ANYSCAN_USE_DPDK" = "1" ] && ! binary_has_dpdk_linkage "$VULNSCANNER_BIN_PATH"; then
	printf '[!] ANYSCAN_USE_DPDK=1 but %s does not link librte_eal.so. Build deps were probably missing — install libdpdk-dev and re-run.\n' \
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
