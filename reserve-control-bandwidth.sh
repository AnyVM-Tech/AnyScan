#!/usr/bin/env bash
# reserve-control-bandwidth.sh
#
# Reserve a guaranteed slice of egress bandwidth for the agentd control
# plane so a saturated zmap port-scan cannot starve heartbeat traffic
# (incident: scan #16, worker 1a was dropped from /api/workers when
# zmap consumed the entire NIC and HTTPS heartbeats timed out).
#
# Architecture:
#   - HTB qdisc on the egress NIC with two classes:
#       1:10  (priority/control)  guaranteed reserve, prio 1
#       1:20  (bulk/scanner)      everything else,    prio 7  (default)
#   - Control-plane traffic is classified into 1:10 by:
#       a) destination IPs resolved from the control URL (direct deploys)
#       b) the cgroup of the bundled tor sidecar service (.onion deploys)
#       c) common tor relay ports (port-based fallback)
#
# Failure mode: log loudly and exit 0 on any error. We must never block
# agentd start because of a tc/iptables policy quirk; the SCANNER_DEFAULT_RATE
# soft cap acts as the secondary defense.
#
# Idempotent: previous qdisc + iptables chain are torn down before reapply.
#
# Configurable via environment (sourced from /etc/agentd/runtime.env when
# invoked by systemd):
#   ANYSCAN_RESERVE_DISABLE              "true" to skip entirely (default: unset)
#   ANYSCAN_RESERVE_INTERFACE            egress NIC, comma-separated for multi-NIC
#                                        deploys; the qdisc + class tree is
#                                        installed on each iface (default:
#                                        default-route iface). Alias:
#                                        ANYSCAN_RESERVE_INTERFACES.
#   ANYSCAN_RESERVE_BANDWIDTH_BPS        reserved control bps  (default: 5000000  = 5 Mbit)
#   ANYSCAN_RESERVE_LINK_RATE_BPS        link ceiling bps      (default: 1000000000 = 1 Gbit)
#   ANYSCAN_CONTROL_PLANE_HOST           comma-separated hosts to classify (default: parsed from CONTROL_URL/AGENT_MANAGEMENT_URL)
#   ANYSCAN_RESERVE_TOR_CGROUP_PATH      cgroup v2 path of tor sidecar (default: system.slice/agentd-tunnel.service)
#   ANYSCAN_RESERVE_TOR_PORTS            comma-separated tor relay ports (default: 9001,9030,9101)
#   ANYSCAN_RESERVE_DRY_RUN              "true" to print actions only
#
# Subcommands:
#   apply    install the qdisc + filters (default)
#   release  tear down the qdisc + filters
#   status   print current state
#
# Exit code is always 0 in apply/release modes.

set -u

LOG_PREFIX='[reserve-control-bandwidth]'
ANYSCAN_RESERVE_CHAIN='ANYSCAN_RESERVE_OUT'

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
    is_true "${ANYSCAN_RESERVE_DRY_RUN:-}"
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

run_cmd_silent() {
    if dry_run; then
        printf '%s DRY-RUN: %s\n' "$LOG_PREFIX" "$*" >&2
        return 0
    fi
    "$@" >/dev/null 2>&1 || return 1
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

# Resolve the list of ifaces this script should manage.
#   - ANYSCAN_RESERVE_INTERFACE / ANYSCAN_RESERVE_INTERFACES (comma or
#     whitespace separated) wins when set.
#   - Otherwise we fall back to the single default-route iface to preserve
#     the legacy single-NIC behavior for hosts that have not been moved
#     to multi-NIC sharding yet.
# Echoes one iface per line so callers can `while read`.
resolve_managed_interfaces() {
    local provided="${ANYSCAN_RESERVE_INTERFACES:-${ANYSCAN_RESERVE_INTERFACE:-}}"
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

extract_host_from_url() {
    local url="${1:-}"
    [ -n "$url" ] || return 1
    # strip scheme://
    local rest="${url#*://}"
    # strip user@ if any
    rest="${rest#*@}"
    # strip path/query/fragment
    rest="${rest%%/*}"
    rest="${rest%%\?*}"
    rest="${rest%%#*}"
    # strip :port
    rest="${rest%%:*}"
    [ -n "$rest" ] || return 1
    printf '%s' "$rest"
}

is_onion_host() {
    case "${1:-}" in
        *.onion|*.onion.) return 0 ;;
    esac
    return 1
}

is_ipv4_literal() {
    local value="${1:-}"
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

resolve_host_to_ips() {
    local host="$1"
    local ips=""
    if command_exists getent; then
        ips="$(getent ahostsv4 "$host" 2>/dev/null | awk '{ print $1 }' | sort -u | tr '\n' ' ' || true)"
    fi
    if [ -z "$ips" ] && command_exists dig; then
        ips="$(dig +short A "$host" 2>/dev/null | grep -E '^[0-9.]+$' | sort -u | tr '\n' ' ' || true)"
    fi
    if [ -z "$ips" ] && command_exists host; then
        ips="$(host -t A "$host" 2>/dev/null | awk '/has address/ { print $NF }' | sort -u | tr '\n' ' ' || true)"
    fi
    printf '%s' "$ips" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//'
}

resolve_control_plane_targets() {
    # Echoes a space-separated list of target hosts (literal IPv4 or hostnames).
    local provided="${ANYSCAN_CONTROL_PLANE_HOST:-}"
    local hosts=""
    if [ -n "$provided" ]; then
        hosts="$(printf '%s' "$provided" | tr ',' ' ')"
    else
        local url
        for env_name in CONTROL_URL AGENT_MANAGEMENT_URL ANYSCAN_WORKER_MANAGEMENT_URL ANYSCAN_API_BASE_URL; do
            url="$(eval "printf '%s' \"\${$env_name:-}\"")"
            [ -n "$url" ] || continue
            local host
            host="$(extract_host_from_url "$url" || true)"
            [ -n "$host" ] || continue
            hosts="$hosts $host"
        done
    fi
    # Deduplicate
    printf '%s' "$hosts" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' '
}

teardown_qdisc() {
    local iface="$1"
    if [ -z "$iface" ]; then
        return 0
    fi
    if dry_run; then
        printf '%s DRY-RUN: tc qdisc del dev %s root\n' "$LOG_PREFIX" "$iface" >&2
        return 0
    fi
    tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
}

teardown_iptables() {
    if ! command_exists iptables; then
        return 0
    fi
    if dry_run; then
        printf '%s DRY-RUN: flush + delete %s chain in mangle/POSTROUTING+OUTPUT\n' \
            "$LOG_PREFIX" "$ANYSCAN_RESERVE_CHAIN" >&2
        return 0
    fi
    # Detach the chain from POSTROUTING and OUTPUT, then flush + delete it.
    while iptables -t mangle -C POSTROUTING -j "$ANYSCAN_RESERVE_CHAIN" 2>/dev/null; do
        iptables -t mangle -D POSTROUTING -j "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || break
    done
    while iptables -t mangle -C OUTPUT -j "$ANYSCAN_RESERVE_CHAIN" 2>/dev/null; do
        iptables -t mangle -D OUTPUT -j "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || break
    done
    iptables -t mangle -F "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
    iptables -t mangle -X "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
}

setup_qdisc() {
    local iface="$1"
    local link_rate_bps="$2"
    local reserve_bps="$3"

    local bulk_rate_bps=$(( link_rate_bps - reserve_bps ))
    if [ "$bulk_rate_bps" -lt 1000 ]; then
        bulk_rate_bps=1000
    fi

    # `tc` accepts `bit` suffix for bits-per-second values directly.
    local link_rate="${link_rate_bps}bit"
    local reserve_rate="${reserve_bps}bit"
    local bulk_rate="${bulk_rate_bps}bit"

    teardown_qdisc "$iface"

    if ! run_cmd tc qdisc add dev "$iface" root handle 1: htb default 20; then
        log "failed to install root HTB qdisc on $iface"
        return 1
    fi
    run_cmd tc class add dev "$iface" parent 1: classid 1:1 \
        htb rate "$link_rate" ceil "$link_rate" || return 1
    run_cmd tc class add dev "$iface" parent 1:1 classid 1:10 \
        htb rate "$reserve_rate" ceil "$link_rate" prio 1 || return 1
    run_cmd tc class add dev "$iface" parent 1:1 classid 1:20 \
        htb rate "$bulk_rate" ceil "$link_rate" prio 7 || return 1
    # Attach SFQ leaves so each class gets fair-queueing.
    run_cmd tc qdisc add dev "$iface" parent 1:10 handle 10: sfq perturb 10 || true
    run_cmd tc qdisc add dev "$iface" parent 1:20 handle 20: sfq perturb 10 || true
    return 0
}

ensure_iptables_chain() {
    if ! command_exists iptables; then
        log "iptables not found; skipping classification rules"
        return 1
    fi
    if dry_run; then
        printf '%s DRY-RUN: create iptables mangle chain %s\n' "$LOG_PREFIX" "$ANYSCAN_RESERVE_CHAIN" >&2
        return 0
    fi
    iptables -t mangle -N "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
    iptables -t mangle -F "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
    if ! iptables -t mangle -C POSTROUTING -j "$ANYSCAN_RESERVE_CHAIN" 2>/dev/null; then
        iptables -t mangle -A POSTROUTING -j "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
    fi
    if ! iptables -t mangle -C OUTPUT -j "$ANYSCAN_RESERVE_CHAIN" 2>/dev/null; then
        iptables -t mangle -A OUTPUT -j "$ANYSCAN_RESERVE_CHAIN" >/dev/null 2>&1 || true
    fi
    return 0
}

classify_destination_host() {
    local host="$1"
    local target

    if is_ipv4_literal "$host"; then
        run_cmd_silent iptables -t mangle -A "$ANYSCAN_RESERVE_CHAIN" \
            -d "$host" -j CLASSIFY --set-class 1:10 \
            && log "classified destination $host as control (1:10)"
        return 0
    fi
    if is_onion_host "$host"; then
        log "skipping .onion host $host (no resolvable IP); relying on tor cgroup match"
        return 0
    fi

    local ips
    ips="$(resolve_host_to_ips "$host")"
    if [ -z "$ips" ]; then
        log "could not resolve $host to IPv4; skipping host filter"
        return 0
    fi
    for target in $ips; do
        run_cmd_silent iptables -t mangle -A "$ANYSCAN_RESERVE_CHAIN" \
            -d "$target" -j CLASSIFY --set-class 1:10 \
            && log "classified $host -> $target as control (1:10)"
    done
}

classify_tor_cgroup() {
    local cg_path="${ANYSCAN_RESERVE_TOR_CGROUP_PATH:-system.slice/agentd-tunnel.service}"
    if [ -z "$cg_path" ]; then
        return 0
    fi
    if run_cmd_silent iptables -t mangle -A "$ANYSCAN_RESERVE_CHAIN" \
        -m cgroup --path "$cg_path" -j CLASSIFY --set-class 1:10; then
        log "classified cgroup $cg_path as control (1:10)"
    else
        log "kernel rejected cgroup path match ($cg_path); ensure tor sidecar runs in this slice or unset ANYSCAN_RESERVE_TOR_CGROUP_PATH"
    fi
}

classify_tor_ports() {
    local ports="${ANYSCAN_RESERVE_TOR_PORTS:-9001,9030,9101}"
    [ -n "$ports" ] || return 0
    if ! run_cmd_silent iptables -t mangle -A "$ANYSCAN_RESERVE_CHAIN" \
        -p tcp -m multiport --dports "$ports" -j CLASSIFY --set-class 1:10; then
        log "failed to install tor port match for $ports"
        return 0
    fi
    log "classified tcp dports $ports as control (1:10)"
}

apply_classification() {
    if ! ensure_iptables_chain; then
        log "no iptables chain — relying on default class only"
        return 0
    fi

    local hosts
    hosts="$(resolve_control_plane_targets)"
    if [ -n "$hosts" ]; then
        local host
        for host in $hosts; do
            classify_destination_host "$host"
        done
    else
        log "no control-plane host configured — set ANYSCAN_CONTROL_PLANE_HOST or CONTROL_URL"
    fi

    classify_tor_cgroup
    classify_tor_ports
}

cmd_apply() {
    if is_true "${ANYSCAN_RESERVE_DISABLE:-}"; then
        log "ANYSCAN_RESERVE_DISABLE is set; skipping"
        return 0
    fi
    if ! command_exists tc; then
        log "tc(8) not found in PATH; skipping bandwidth reservation"
        return 0
    fi

    local interfaces
    interfaces="$(resolve_managed_interfaces)"
    if [ -z "$interfaces" ]; then
        log "could not determine egress interface; skipping"
        return 0
    fi

    local link_rate_bps="${ANYSCAN_RESERVE_LINK_RATE_BPS:-1000000000}"
    local reserve_bps="${ANYSCAN_RESERVE_BANDWIDTH_BPS:-5000000}"
    if ! [[ "$link_rate_bps" =~ ^[0-9]+$ ]] || [ "$link_rate_bps" -lt 1000 ]; then
        log "ANYSCAN_RESERVE_LINK_RATE_BPS=$link_rate_bps invalid; using 1000000000"
        link_rate_bps=1000000000
    fi
    if ! [[ "$reserve_bps" =~ ^[0-9]+$ ]] || [ "$reserve_bps" -lt 1000 ]; then
        log "ANYSCAN_RESERVE_BANDWIDTH_BPS=$reserve_bps invalid; using 5000000"
        reserve_bps=5000000
    fi
    if [ "$reserve_bps" -ge "$link_rate_bps" ]; then
        log "reserve ($reserve_bps) >= link rate ($link_rate_bps); clamping reserve to half of link rate"
        reserve_bps=$(( link_rate_bps / 2 ))
    fi

    # iptables CLASSIFY rules are not iface-bound, so we install the
    # mangle chain once and let it apply across every NIC the qdisc tree
    # gets installed on below.
    apply_classification

    local iface
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        log "applying egress reservation on $iface: control=${reserve_bps}bps reserve, link=${link_rate_bps}bps ceiling"
        if ! setup_qdisc "$iface" "$link_rate_bps" "$reserve_bps"; then
            log "qdisc setup failed on $iface; tearing down partial state"
            teardown_qdisc "$iface"
            continue
        fi
        log "reservation active on $iface"
    done <<<"$interfaces"
    return 0
}

cmd_release() {
    if ! command_exists tc; then
        return 0
    fi
    local interfaces iface
    interfaces="$(resolve_managed_interfaces)"
    teardown_iptables
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        teardown_qdisc "$iface"
        log "released reservation on $iface"
    done <<<"$interfaces"
    return 0
}

cmd_status() {
    local interfaces iface
    interfaces="$(resolve_managed_interfaces)"
    if [ -z "$interfaces" ]; then
        printf '%s no interface\n' "$LOG_PREFIX"
        return 0
    fi
    while IFS= read -r iface; do
        [ -n "$iface" ] || continue
        printf '== qdisc on %s ==\n' "$iface"
        tc -s qdisc show dev "$iface" 2>/dev/null || true
        printf '\n== classes on %s ==\n' "$iface"
        tc -s class show dev "$iface" 2>/dev/null || true
        printf '\n'
    done <<<"$interfaces"
    if command_exists iptables; then
        printf '== iptables mangle %s ==\n' "$ANYSCAN_RESERVE_CHAIN"
        iptables -t mangle -S "$ANYSCAN_RESERVE_CHAIN" 2>/dev/null \
            || printf '%s chain not present\n' "$ANYSCAN_RESERVE_CHAIN"
    fi
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
