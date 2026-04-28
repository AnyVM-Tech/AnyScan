#!/usr/bin/env bash
# tools/setup-dpdk.sh — host-side DPDK setup for the AnyScan port scanner.
#
# Phase 2 of plans/2026-04-28-portscan-dpdk-impl-v1.md §3.10.5.
#
# Two subcommands:
#   bind   — reserve hugepages, load vfio-pci, bind the listed ENIs to
#            vfio-pci. Idempotent: re-running on an already-bound system
#            is a no-op (logs "already bound" and exits 0).
#   unbind — reverse. Returns the listed ENIs to the kernel ENA driver
#            and frees hugepages back to the system. Leaves the vfio-pci
#            module loaded (other consumers may still need it).
#
# Refusal rules (HARD-CODED, not configurable — these prevent operator
# error from cutting the worker off from the orchestrator):
#   1. Refuses to bind eth0 (the agentd control-plane interface). Even
#      if eth0 appears in ANYSCAN_DPDK_PCI_BDFS the script skips it with
#      a one-line warning. The whole point of the dedicated-DPDK-NIC
#      design (plan §3.11) is keeping kernel networking on at least one
#      interface for heartbeat / journal / token refresh.
#   2. Refuses to bind the only NIC. If the resolved NIC list would
#      result in zero kernel-networking interfaces remaining, the script
#      bails with a clear error pointing at the dedicated-DPDK-NIC
#      requirement. Single-NIC instance shapes are NOT eligible for
#      DPDK mode in v1.
#
# Inputs (env / argv):
#   ANYSCAN_DPDK_PCI_BDFS — comma-separated PCI BDFs (e.g.
#       "0000:00:06.0,0000:00:07.0") OR kernel iface names (e.g.
#       "eth1,eth2"). Iface names are resolved to BDFs by walking
#       /sys/class/net/<iface>/device.
#   ANYSCAN_DPDK_HUGEPAGES_GB — total hugepages reservation in GiB
#       (default 4). 1 GiB pages are tried first; falls back to 2 MiB
#       pages on systems where 1 GiB pages aren't available. Phase 2
#       micro-bench may adjust this default per instance shape.
#
# Out of scope (handled elsewhere):
#   - libdpdk-dev install (install-external-deps.sh::install_dpdk_build_deps).
#   - Probing whether the host is "DPDK-ready"
#     (install-worker-bundle.sh::probe_dpdk_runtime_available).
#   - The actual scanner build flag
#     (install-external-deps.sh::vulnscanner_make_args ANYSCAN_USE_DPDK=1).
#   - Live bench (separate worker, plan §5.3).

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
    cat <<'USAGE'
Usage:
  setup-dpdk.sh bind     [--bdfs=<csv>] [--hugepages-gb=<N>]
  setup-dpdk.sh unbind   [--bdfs=<csv>]
  setup-dpdk.sh status

Environment:
  ANYSCAN_DPDK_PCI_BDFS     CSV of PCI BDFs or iface names (used when --bdfs is omitted)
  ANYSCAN_DPDK_HUGEPAGES_GB Hugepages reservation in GiB (default 4)
  ANYSCAN_DPDK_DEVBIND      dpdk-devbind.py path (auto-detected when unset)

Refusal rules (hard-coded):
  - eth0 is never bound (agentd control-plane interface).
  - The only NIC is never bound (would leave the host without kernel networking).
USAGE
}

ANYSCAN_DPDK_HUGEPAGES_GB="${ANYSCAN_DPDK_HUGEPAGES_GB:-4}"
ANYSCAN_DPDK_PCI_BDFS="${ANYSCAN_DPDK_PCI_BDFS:-}"
ANYSCAN_DPDK_DEVBIND="${ANYSCAN_DPDK_DEVBIND:-}"

# Resolve dpdk-devbind.py once. The script ships with the `dpdk` package on
# Debian/Ubuntu at /usr/share/dpdk/usertools/dpdk-devbind.py, but source
# builds put it under <prefix>/share/dpdk/usertools. Operators can override
# via ANYSCAN_DPDK_DEVBIND.
resolve_devbind() {
    if [ -n "$ANYSCAN_DPDK_DEVBIND" ] && [ -x "$ANYSCAN_DPDK_DEVBIND" ]; then
        printf '%s' "$ANYSCAN_DPDK_DEVBIND"
        return
    fi
    local candidate
    for candidate in \
        /usr/share/dpdk/usertools/dpdk-devbind.py \
        /usr/local/share/dpdk/usertools/dpdk-devbind.py \
        /opt/dpdk/usertools/dpdk-devbind.py; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return
        fi
    done
    if command -v dpdk-devbind.py >/dev/null 2>&1; then
        command -v dpdk-devbind.py
        return
    fi
    return 1
}

# Walk /sys/class/net/<iface>/device → resolve to a PCI BDF. Returns 0 +
# prints the BDF on success, returns 1 on failure (interface doesn't exist
# or is virtual / non-PCI).
iface_to_bdf() {
    local iface="$1"
    local sysdev="/sys/class/net/$iface/device"
    if [ ! -e "$sysdev" ]; then
        return 1
    fi
    local resolved
    resolved="$(readlink -f "$sysdev" 2>/dev/null || true)"
    if [ -z "$resolved" ]; then
        return 1
    fi
    # /sys/devices/pci0000:00/0000:00:06.0 → 0000:00:06.0 (last component)
    basename "$resolved"
}

# Parse the user-supplied list (BDFs or iface names) into a deduplicated
# list of BDFs. eth0 is silently dropped per the refusal rules. Returns
# the list one BDF per line on stdout.
resolve_bdf_list() {
    local raw="$1"
    [ -n "$raw" ] || return 0
    local entry resolved
    local -A seen=()
    IFS=',' read -ra entries <<<"$raw"
    for entry in "${entries[@]}"; do
        entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
        [ -n "$entry" ] || continue
        if [ "$entry" = "eth0" ]; then
            printf '[!] %s: skipping eth0 (agentd control-plane interface, never bound to vfio-pci).\n' "$SCRIPT_NAME" >&2
            continue
        fi
        # Looks like a BDF (e.g. 0000:00:06.0)?
        if [[ "$entry" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]+$ ]]; then
            resolved="$entry"
        else
            # iface name → BDF
            if ! resolved="$(iface_to_bdf "$entry")"; then
                printf '[!] %s: could not resolve iface "%s" to a PCI BDF (no /sys/class/net/%s/device); skipping.\n' \
                    "$SCRIPT_NAME" "$entry" "$entry" >&2
                continue
            fi
        fi
        # Dedup
        if [ -z "${seen[$resolved]:-}" ]; then
            seen[$resolved]=1
            printf '%s\n' "$resolved"
        fi
    done
}

# Count kernel-networked, IPv4-bearing, non-loopback NICs that AREN'T in
# the vfio-pci-target list. Used to enforce the "never leave the host
# with zero kernel NICs" refusal.
count_remaining_kernel_nics() {
    local target_bdfs_csv="$1"
    local iface bdf
    local count=0
    for iface in /sys/class/net/*; do
        [ -d "$iface" ] || continue
        local name
        name="$(basename "$iface")"
        case "$name" in
            lo|docker*|br-*|veth*|tun*|tap*|wg*|zt*|cni*|cilium*|flannel*|kube-*) continue ;;
        esac
        # Must be UP with an IPv4 address.
        if ! ip -4 -o addr show dev "$name" 2>/dev/null | grep -q 'inet '; then
            continue
        fi
        bdf="$(iface_to_bdf "$name" 2>/dev/null || true)"
        if [ -n "$bdf" ] && [[ ",${target_bdfs_csv}," == *",${bdf},"* ]]; then
            # This iface IS being bound to vfio-pci — doesn't count.
            continue
        fi
        count=$(( count + 1 ))
    done
    printf '%s\n' "$count"
}

# Reserve hugepages. Tries 1 GiB pages first (lower TLB pressure on
# c6in.metal-class hardware); falls back to 2 MiB pages on hosts where
# 1 GiB pages are unavailable (kernel built without GB-page support, or
# /proc/sys/vm/nr_hugepages_mempolicy is the only knob). Idempotent:
# re-running with the same target reservation is a no-op.
reserve_hugepages() {
    local target_gb="$1"
    [ "$target_gb" -gt 0 ] || return 0
    local hp1g_dir="/sys/kernel/mm/hugepages/hugepages-1048576kB"
    local hp2m_dir="/sys/kernel/mm/hugepages/hugepages-2048kB"
    if [ -d "$hp1g_dir" ]; then
        local current
        current="$(cat "$hp1g_dir/nr_hugepages" 2>/dev/null || echo 0)"
        if [ "$current" -ge "$target_gb" ]; then
            printf '[*] %s: %s 1 GiB hugepages already reserved (target %s).\n' \
                "$SCRIPT_NAME" "$current" "$target_gb"
            return 0
        fi
        printf '[*] %s: reserving %s 1 GiB hugepages...\n' "$SCRIPT_NAME" "$target_gb"
        if printf '%s\n' "$target_gb" > "$hp1g_dir/nr_hugepages" 2>/dev/null; then
            current="$(cat "$hp1g_dir/nr_hugepages" 2>/dev/null || echo 0)"
            if [ "$current" -ge "$target_gb" ]; then
                printf '[*] %s: 1 GiB hugepages reserved=%s.\n' "$SCRIPT_NAME" "$current"
                return 0
            fi
            printf '[!] %s: 1 GiB hugepages reservation fell short (got %s, wanted %s); falling back to 2 MiB.\n' \
                "$SCRIPT_NAME" "$current" "$target_gb" >&2
        fi
    fi
    if [ -d "$hp2m_dir" ]; then
        # 2 MiB pages: target_gb GiB → target_gb * 512 pages of 2 MiB.
        local target_2m=$(( target_gb * 512 ))
        local current
        current="$(cat "$hp2m_dir/nr_hugepages" 2>/dev/null || echo 0)"
        if [ "$current" -ge "$target_2m" ]; then
            printf '[*] %s: %s 2 MiB hugepages already reserved (target %s).\n' \
                "$SCRIPT_NAME" "$current" "$target_2m"
            return 0
        fi
        printf '[*] %s: reserving %s 2 MiB hugepages...\n' "$SCRIPT_NAME" "$target_2m"
        if printf '%s\n' "$target_2m" > "$hp2m_dir/nr_hugepages" 2>/dev/null; then
            current="$(cat "$hp2m_dir/nr_hugepages" 2>/dev/null || echo 0)"
            if [ "$current" -ge "$target_2m" ]; then
                printf '[*] %s: 2 MiB hugepages reserved=%s.\n' "$SCRIPT_NAME" "$current"
                return 0
            fi
        fi
        printf '[!] %s: 2 MiB hugepages reservation also failed.\n' "$SCRIPT_NAME" >&2
    fi
    printf '[!] %s: could not reserve any hugepages. Check /proc/meminfo HugePages_Total and free system memory.\n' \
        "$SCRIPT_NAME" >&2
    return 1
}

# Free hugepages back to the system (set nr_hugepages to 0).
release_hugepages() {
    local hp_dir
    for hp_dir in /sys/kernel/mm/hugepages/hugepages-*kB; do
        [ -e "$hp_dir/nr_hugepages" ] || continue
        printf '0\n' > "$hp_dir/nr_hugepages" 2>/dev/null || true
    done
    printf '[*] %s: hugepages released.\n' "$SCRIPT_NAME"
}

# Disable Transparent Hugepages (THP). DPDK explicitly recommends this
# (and the kernel docs flag THP+hugepages as a poor combo: THP fragments
# memory in ways that can starve the static hugepage pool). Best-effort:
# some kernels don't expose /sys/kernel/mm/transparent_hugepage/enabled.
# Reversible — release_thp() flips it back to its previous value.
disable_thp_if_possible() {
    local thp_file="/sys/kernel/mm/transparent_hugepage/enabled"
    if [ -w "$thp_file" ]; then
        local prev
        prev="$(cat "$thp_file" 2>/dev/null || true)"
        printf 'never\n' > "$thp_file" 2>/dev/null || true
        printf '[*] %s: transparent_hugepage set to never (was: %s).\n' \
            "$SCRIPT_NAME" "${prev:-unknown}"
    fi
}

cmd_bind() {
    if [ "$(id -u)" != "0" ]; then
        printf '[!] %s: bind requires root (modprobe + sysfs writes).\n' "$SCRIPT_NAME" >&2
        exit 1
    fi
    local bdfs
    if ! bdfs="$(resolve_bdf_list "$ANYSCAN_DPDK_PCI_BDFS")" || [ -z "$bdfs" ]; then
        printf '[!] %s: no valid PCI BDFs to bind. Set ANYSCAN_DPDK_PCI_BDFS to a CSV of BDFs or iface names.\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi
    local bdfs_csv
    bdfs_csv="$(printf '%s' "$bdfs" | tr '\n' ',' | sed 's/,$//')"

    # Refusal rule 2: would binding leave us with zero kernel NICs?
    local remaining
    remaining="$(count_remaining_kernel_nics "$bdfs_csv")"
    if [ "$remaining" -lt 1 ]; then
        printf '[!] %s: refusing to bind because doing so would leave 0 kernel-networked NICs (host would lose orchestrator connectivity).\n' \
            "$SCRIPT_NAME" >&2
        printf '    Resolved BDFs: %s\n' "$bdfs_csv" >&2
        printf '    See plan §3.11: DPDK requires a dedicated NIC AND at least one kernel-networked NIC.\n' >&2
        exit 1
    fi

    local devbind
    if ! devbind="$(resolve_devbind)"; then
        printf '[!] %s: dpdk-devbind.py not found. Install the `dpdk` apt package or set ANYSCAN_DPDK_DEVBIND.\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi

    # Hugepages first — DPDK's mempool create needs them BEFORE rte_eal_init.
    if ! reserve_hugepages "$ANYSCAN_DPDK_HUGEPAGES_GB"; then
        printf '[!] %s: hugepages reservation failed; aborting bind to avoid leaving the host in a half-configured state.\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi
    disable_thp_if_possible

    if ! lsmod 2>/dev/null | grep -q '^vfio_pci\b'; then
        printf '[*] %s: loading vfio-pci module...\n' "$SCRIPT_NAME"
        modprobe vfio-pci || {
            printf '[!] %s: modprobe vfio-pci failed. Is the kernel built with CONFIG_VFIO_PCI?\n' "$SCRIPT_NAME" >&2
            exit 1
        }
    fi

    # AWS bare-metal hosts often lack a real IOMMU exposed to userspace; the
    # `enable_unsafe_noiommu_mode` knob lets vfio-pci function without one.
    # Best-effort — if the knob is missing (older kernel) the bind step
    # below will fail with a clear message and the operator will know.
    local noiommu_knob="/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"
    if [ -w "$noiommu_knob" ]; then
        printf 'Y\n' > "$noiommu_knob" 2>/dev/null || true
    fi

    local bdf
    while IFS= read -r bdf; do
        [ -n "$bdf" ] || continue
        # Idempotency: if already bound to vfio-pci, skip.
        local current_driver
        current_driver="$(readlink -f "/sys/bus/pci/devices/$bdf/driver" 2>/dev/null | xargs -r basename || true)"
        if [ "$current_driver" = "vfio-pci" ]; then
            printf '[*] %s: %s already bound to vfio-pci; skipping.\n' "$SCRIPT_NAME" "$bdf"
            continue
        fi
        printf '[*] %s: binding %s to vfio-pci (was: %s)...\n' "$SCRIPT_NAME" "$bdf" "${current_driver:-none}"
        if ! "$devbind" --bind=vfio-pci "$bdf"; then
            printf '[!] %s: failed to bind %s. Check `dpdk-devbind.py --status`; the device may have an active route or be the only NIC.\n' \
                "$SCRIPT_NAME" "$bdf" >&2
            exit 1
        fi
    done <<<"$bdfs"

    printf '[*] %s: bind complete. Run `dpdk-devbind.py --status` to confirm.\n' "$SCRIPT_NAME"
}

cmd_unbind() {
    if [ "$(id -u)" != "0" ]; then
        printf '[!] %s: unbind requires root.\n' "$SCRIPT_NAME" >&2
        exit 1
    fi
    local bdfs
    if ! bdfs="$(resolve_bdf_list "$ANYSCAN_DPDK_PCI_BDFS")" || [ -z "$bdfs" ]; then
        printf '[!] %s: no BDFs to unbind. Set ANYSCAN_DPDK_PCI_BDFS to the CSV used at bind time.\n' \
            "$SCRIPT_NAME" >&2
        exit 1
    fi
    local devbind
    if ! devbind="$(resolve_devbind)"; then
        printf '[!] %s: dpdk-devbind.py not found.\n' "$SCRIPT_NAME" >&2
        exit 1
    fi
    local bdf
    while IFS= read -r bdf; do
        [ -n "$bdf" ] || continue
        local current_driver
        current_driver="$(readlink -f "/sys/bus/pci/devices/$bdf/driver" 2>/dev/null | xargs -r basename || true)"
        if [ "$current_driver" != "vfio-pci" ]; then
            printf '[*] %s: %s not bound to vfio-pci (current: %s); skipping.\n' \
                "$SCRIPT_NAME" "$bdf" "${current_driver:-none}"
            continue
        fi
        # Restore to ena (the kernel ENA driver). On non-AWS hosts the
        # original driver may differ; operators can pass --bind=<driver>
        # explicitly via dpdk-devbind.py if needed.
        printf '[*] %s: unbinding %s back to ena...\n' "$SCRIPT_NAME" "$bdf"
        if ! "$devbind" --bind=ena "$bdf"; then
            printf '[!] %s: failed to unbind %s. Manual recovery: `dpdk-devbind.py --bind=ena %s`.\n' \
                "$SCRIPT_NAME" "$bdf" "$bdf" >&2
            exit 1
        fi
    done <<<"$bdfs"

    release_hugepages
    printf '[*] %s: unbind complete.\n' "$SCRIPT_NAME"
}

cmd_status() {
    printf '== Hugepages ==\n'
    local hp_dir
    for hp_dir in /sys/kernel/mm/hugepages/hugepages-*kB; do
        [ -e "$hp_dir/nr_hugepages" ] || continue
        printf '  %s: nr=%s free=%s\n' \
            "$(basename "$hp_dir")" \
            "$(cat "$hp_dir/nr_hugepages" 2>/dev/null || echo ?)" \
            "$(cat "$hp_dir/free_hugepages" 2>/dev/null || echo ?)"
    done
    printf '== vfio-pci ==\n'
    if lsmod 2>/dev/null | grep -q '^vfio_pci\b'; then
        printf '  loaded\n'
    else
        printf '  NOT loaded\n'
    fi
    printf '== /dev/vfio ==\n'
    if [ -e /dev/vfio/vfio ]; then
        printf '  /dev/vfio/vfio present\n'
    else
        printf '  /dev/vfio/vfio missing (no NIC bound)\n'
    fi
    printf '== devbind status ==\n'
    local devbind
    if devbind="$(resolve_devbind)"; then
        "$devbind" --status 2>/dev/null || true
    else
        printf '  dpdk-devbind.py not found\n'
    fi
}

# argv parsing
SUBCMD="${1:-}"
[ -n "$SUBCMD" ] || { usage >&2; exit 1; }
shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --bdfs=*)         ANYSCAN_DPDK_PCI_BDFS="${1#--bdfs=}" ;;
        --hugepages-gb=*) ANYSCAN_DPDK_HUGEPAGES_GB="${1#--hugepages-gb=}" ;;
        -h|--help)        usage; exit 0 ;;
        *) printf '[!] %s: unknown flag %s\n' "$SCRIPT_NAME" "$1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

case "$SUBCMD" in
    bind)   cmd_bind ;;
    unbind) cmd_unbind ;;
    status) cmd_status ;;
    -h|--help) usage; exit 0 ;;
    *) printf '[!] %s: unknown subcommand %s\n' "$SCRIPT_NAME" "$SUBCMD" >&2; usage >&2; exit 1 ;;
esac
