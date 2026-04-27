#!/usr/bin/env bash
# tune-scanner-host.sh
#
# Apply host-level kernel and NIC tunings that let the bundled scanner
# sustain >500k pps without the kernel dropping packets in the qdisc or
# the AF_PACKET capture queue. Companion to reserve-control-bandwidth.sh
# (PR #28): that script protects control-plane heartbeats from a busy
# scanner; this one stops the busy scanner from being throttled by the
# host's default sysctl values, which are sized for a typical desktop.
#
# Tunings applied (all idempotent, all fail-open):
#   net.core.netdev_max_backlog   1000   ->  30000   per-CPU input queue
#   net.core.optmem_max          81920   -> 524288   ancillary skb memory
#   net.core.rmem_max          212992    -> 16777216 max socket recv buf
#   net.core.wmem_max          212992    -> 16777216 max socket send buf
#   net.ipv4.ip_local_port_range  --     -> 10000-65535  ephemeral pool
#   <iface>/tx_queue_len         1000    -> 10000   egress queue depth
#
# net.core.netdev_max_backlog is the dominant lever above ~200k pps: when
# the scanner's sender threads enqueue faster than NAPI can drain into the
# qdisc, the default 1000-slot backlog overflows and softirq drops climb.
# net.core.optmem_max governs the per-skb ancillary buffer (timestamps,
# vlan tags) the AF_PACKET receiver pulls from; 80k caps at roughly
# ~1k concurrent AF_PACKET frames before it starts allocating from
# slab and stalling.
#
# Persistence:
#   Tunings are written to /etc/sysctl.d/99-anyscan-scanner.conf so they
#   survive reboot and are re-applied by systemd-sysctl.service. The
#   txqueuelen value is set live via `ip link set` because txqueuelen is
#   not a sysctl. NIC down/up events reset txqueuelen, so this script is
#   wired into the worker unit's ExecStartPre to refresh it on each start.
#
# Failure mode: log loudly and exit 0 on every error. Like
# reserve-control-bandwidth.sh, we must never block the worker from
# starting because of a sysctl quirk. The bundled scanner still works
# at default sysctl values; it just hits the soft ceiling sooner.
#
# Configurable via environment (sourced from /etc/agentd/runtime.env when
# invoked by systemd):
#   ANYSCAN_TUNE_DISABLE                "true" to skip entirely (default: unset)
#   ANYSCAN_TUNE_INTERFACE              egress NIC, comma-separated for
#                                        multi-NIC deploys; the txqueuelen
#                                        bump is applied to each iface in
#                                        the list (default: default-route
#                                        iface). Alias: ANYSCAN_TUNE_INTERFACES.
#   ANYSCAN_TUNE_TXQUEUELEN             tx_queue_len (default: 10000)
#   ANYSCAN_TUNE_NETDEV_MAX_BACKLOG     netdev_max_backlog (default: 30000)
#   ANYSCAN_TUNE_OPTMEM_MAX             optmem_max (default: 524288)
#   ANYSCAN_TUNE_SOCK_MEM_MAX           rmem_max + wmem_max (default: 16777216)
#   ANYSCAN_TUNE_LOCAL_PORT_RANGE       local port range (default: "10000 65535")
#   ANYSCAN_TUNE_SYSCTL_FILE            sysctl drop-in path (default: /etc/sysctl.d/99-anyscan-scanner.conf)
#   ANYSCAN_TUNE_DRY_RUN                "true" to print actions only
#
# Subcommands:
#   apply    write the sysctl drop-in, apply it, and bump txqueuelen (default)
#   release  remove the sysctl drop-in and restore txqueuelen to 1000
#   status   print current values
#
# Exit code is always 0 in apply/release modes.

set -u

LOG_PREFIX='[tune-scanner-host]'
DEFAULT_SYSCTL_FILE='/etc/sysctl.d/99-anyscan-scanner.conf'
DEFAULT_TXQUEUELEN=10000
DEFAULT_NETDEV_MAX_BACKLOG=30000
DEFAULT_OPTMEM_MAX=524288
DEFAULT_SOCK_MEM_MAX=16777216
DEFAULT_LOCAL_PORT_RANGE='10000 65535'

log() {
    printf '%s %s\n' "$LOG_PREFIX" "$*" >&2
}

is_true() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    esac
    return 1
}

dry_run() {
    is_true "${ANYSCAN_TUNE_DRY_RUN:-}"
}

run_cmd() {
    if dry_run; then
        printf '%s DRY-RUN: %s\n' "$LOG_PREFIX" "$*" >&2
        return 0
    fi
    if ! "$@"; then
        log "command failed (continuing): $*"
        return 1
    fi
    return 0
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

detect_default_interface() {
    local value=""
    if command_exists ip; then
        value="$(ip -4 route show default 2>/dev/null \
            | awk 'NF { for (i=1; i<=NF; i++) if ($i == "dev" && (i+1) <= NF) { print $(i+1); exit } }' \
            || true)"
    fi
    if [ -z "$value" ] && [ -r /proc/net/route ]; then
        value="$(awk 'NR > 1 && $2 == "00000000" { print $1; exit }' /proc/net/route 2>/dev/null || true)"
    fi
    printf '%s' "${value:-}" | tr -d '[:space:]'
}

resolve_iface() {
    local iface="${ANYSCAN_TUNE_INTERFACE:-}"
    if [ -z "$iface" ]; then
        iface="$(detect_default_interface || true)"
    fi
    printf '%s' "$iface"
}

# Echoes one iface per line, expanding the comma/whitespace-separated value
# from ANYSCAN_TUNE_INTERFACES (or the legacy ANYSCAN_TUNE_INTERFACE) and
# falling back to the default-route iface. Multi-NIC sharded scanners
# need txqueuelen bumped on every NIC the scanner will drive, not just
# the default-route one.
resolve_ifaces() {
    local provided="${ANYSCAN_TUNE_INTERFACES:-${ANYSCAN_TUNE_INTERFACE:-}}"
    local out=""
    if [ -n "$provided" ]; then
        local entry
        for entry in $(printf '%s' "$provided" | tr ',;' '  '); do
            entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
            [ -n "$entry" ] || continue
            case " $out " in
                *" $entry "*) continue ;;
            esac
            if [ -z "$out" ]; then
                out="$entry"
            else
                out="$out $entry"
            fi
        done
    fi
    if [ -z "$out" ]; then
        out="$(detect_default_interface || true)"
    fi
    [ -n "$out" ] || return 0
    local entry
    for entry in $out; do
        printf '%s\n' "$entry"
    done
}

resolve_uint() {
    local name="$1"
    local value="$2"
    local default="$3"
    if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -gt 0 ]; then
        printf '%s' "$value"
        return 0
    fi
    if [ -n "$value" ]; then
        log "$name=$value invalid; using default $default"
    fi
    printf '%s' "$default"
}

write_sysctl_dropin() {
    local target="$1"
    local backlog="$2"
    local optmem="$3"
    local sockmem="$4"
    local port_range="$5"

    if dry_run; then
        printf '%s DRY-RUN: write sysctl drop-in to %s\n' "$LOG_PREFIX" "$target" >&2
        return 0
    fi

    local tmp
    tmp="$(mktemp)" || {
        log "mktemp failed; cannot write sysctl drop-in"
        return 1
    }
    cat >"$tmp" <<EOF
# Managed by tune-scanner-host.sh — do not edit by hand. Run
# tune-scanner-host.sh release to remove these tunings.
net.core.netdev_max_backlog = $backlog
net.core.optmem_max = $optmem
net.core.rmem_max = $sockmem
net.core.wmem_max = $sockmem
net.ipv4.ip_local_port_range = $port_range
EOF
    local target_dir
    target_dir="$(dirname "$target")"
    if [ ! -d "$target_dir" ]; then
        if ! mkdir -p "$target_dir" 2>/dev/null; then
            log "mkdir $target_dir failed; skipping sysctl drop-in"
            rm -f "$tmp"
            return 1
        fi
    fi
    if ! install -m 0644 "$tmp" "$target" 2>/dev/null; then
        log "install $tmp -> $target failed; skipping sysctl drop-in"
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    log "wrote sysctl drop-in $target"
    return 0
}

apply_sysctl() {
    local target="$1"
    if dry_run; then
        printf '%s DRY-RUN: sysctl -p %s\n' "$LOG_PREFIX" "$target" >&2
        return 0
    fi
    if ! command_exists sysctl; then
        log "sysctl(8) not found; drop-in will be applied at next boot by systemd-sysctl.service"
        return 0
    fi
    # `sysctl -p` returns non-zero if any one tunable rejected; we still want
    # to log and continue so a single bad knob does not block startup.
    if sysctl -p "$target" >/dev/null 2>&1; then
        log "applied sysctl values from $target"
        return 0
    fi
    log "sysctl -p $target reported errors; some values may not be live (drop-in still persists for next boot)"
    return 0
}

set_txqueuelen() {
    local iface="$1"
    local target_len="$2"
    if [ -z "$iface" ]; then
        return 0
    fi
    if ! command_exists ip; then
        log "ip(8) not found; cannot set txqueuelen on $iface"
        return 0
    fi
    if [ ! -e "/sys/class/net/$iface" ]; then
        log "interface $iface not present; skipping txqueuelen"
        return 0
    fi
    local current
    current="$(cat "/sys/class/net/$iface/tx_queue_len" 2>/dev/null || true)"
    if [ "$current" = "$target_len" ]; then
        log "txqueuelen on $iface already $target_len"
        return 0
    fi
    if dry_run; then
        printf '%s DRY-RUN: ip link set dev %s txqueuelen %s\n' "$LOG_PREFIX" "$iface" "$target_len" >&2
        return 0
    fi
    if ip link set dev "$iface" txqueuelen "$target_len" 2>/dev/null; then
        log "set txqueuelen on $iface: $current -> $target_len"
    else
        log "ip link set txqueuelen on $iface failed (need CAP_NET_ADMIN); leaving at $current"
    fi
    return 0
}

cmd_apply() {
    if is_true "${ANYSCAN_TUNE_DISABLE:-}"; then
        log "ANYSCAN_TUNE_DISABLE is set; skipping"
        return 0
    fi

    local target="${ANYSCAN_TUNE_SYSCTL_FILE:-$DEFAULT_SYSCTL_FILE}"
    local txqueuelen
    local backlog
    local optmem
    local sockmem
    local port_range

    txqueuelen="$(resolve_uint ANYSCAN_TUNE_TXQUEUELEN "${ANYSCAN_TUNE_TXQUEUELEN:-}" "$DEFAULT_TXQUEUELEN")"
    backlog="$(resolve_uint ANYSCAN_TUNE_NETDEV_MAX_BACKLOG "${ANYSCAN_TUNE_NETDEV_MAX_BACKLOG:-}" "$DEFAULT_NETDEV_MAX_BACKLOG")"
    optmem="$(resolve_uint ANYSCAN_TUNE_OPTMEM_MAX "${ANYSCAN_TUNE_OPTMEM_MAX:-}" "$DEFAULT_OPTMEM_MAX")"
    sockmem="$(resolve_uint ANYSCAN_TUNE_SOCK_MEM_MAX "${ANYSCAN_TUNE_SOCK_MEM_MAX:-}" "$DEFAULT_SOCK_MEM_MAX")"
    port_range="${ANYSCAN_TUNE_LOCAL_PORT_RANGE:-$DEFAULT_LOCAL_PORT_RANGE}"
    if ! [[ "$port_range" =~ ^[0-9]+[[:space:]]+[0-9]+$ ]]; then
        log "ANYSCAN_TUNE_LOCAL_PORT_RANGE='$port_range' invalid; using default '$DEFAULT_LOCAL_PORT_RANGE'"
        port_range="$DEFAULT_LOCAL_PORT_RANGE"
    fi

    write_sysctl_dropin "$target" "$backlog" "$optmem" "$sockmem" "$port_range"
    apply_sysctl "$target"

    local ifaces iface ifaces_applied=""
    ifaces="$(resolve_ifaces)"
    if [ -z "$ifaces" ]; then
        log "could not determine egress interface; skipping txqueuelen"
    else
        while IFS= read -r iface; do
            [ -n "$iface" ] || continue
            set_txqueuelen "$iface" "$txqueuelen"
            if [ -z "$ifaces_applied" ]; then
                ifaces_applied="$iface"
            else
                ifaces_applied="$ifaces_applied,$iface"
            fi
        done <<<"$ifaces"
    fi

    log "tunings applied (sysctl=$target txqueuelen_iface=${ifaces_applied:-none})"
    return 0
}

cmd_release() {
    local target="${ANYSCAN_TUNE_SYSCTL_FILE:-$DEFAULT_SYSCTL_FILE}"
    if [ -f "$target" ]; then
        if dry_run; then
            printf '%s DRY-RUN: rm %s\n' "$LOG_PREFIX" "$target" >&2
        elif rm -f "$target" 2>/dev/null; then
            log "removed sysctl drop-in $target (reboot or sysctl --system to revert)"
        else
            log "rm $target failed; sysctl drop-in still in place"
        fi
    fi
    local ifaces iface
    ifaces="$(resolve_ifaces)"
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        set_txqueuelen "$iface" 1000
    done <<<"$ifaces"
    return 0
}

cmd_status() {
    local target="${ANYSCAN_TUNE_SYSCTL_FILE:-$DEFAULT_SYSCTL_FILE}"
    printf '== sysctl drop-in %s ==\n' "$target"
    if [ -f "$target" ]; then
        cat "$target"
    else
        printf '(absent)\n'
    fi
    printf '\n== live sysctl values ==\n'
    if command_exists sysctl; then
        sysctl net.core.netdev_max_backlog \
               net.core.optmem_max \
               net.core.rmem_max \
               net.core.wmem_max \
               net.ipv4.ip_local_port_range 2>/dev/null
    else
        for k in netdev_max_backlog optmem_max rmem_max wmem_max; do
            printf 'net.core.%s = %s\n' "$k" "$(cat "/proc/sys/net/core/$k" 2>/dev/null || printf '?')"
        done
        printf 'net.ipv4.ip_local_port_range = %s\n' \
            "$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || printf '?')"
    fi
    local ifaces iface
    ifaces="$(resolve_ifaces)"
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        printf '\n== %s txqueuelen ==\n' "$iface"
        cat "/sys/class/net/$iface/tx_queue_len" 2>/dev/null || printf 'unknown\n'
    done <<<"$ifaces"
    return 0
}

main() {
    local action="${1:-apply}"
    case "$action" in
        apply)   cmd_apply ;;
        release) cmd_release ;;
        status)  cmd_status ;;
        -h|--help|help)
            grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'
            ;;
        *)
            log "unknown action: $action (expected apply|release|status)"
            return 0
            ;;
    esac
}

main "$@"
exit 0
