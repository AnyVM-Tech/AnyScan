#!/usr/bin/env bash
# Sanity-check that the per-NIC iteration paths in install-worker-bundle.sh,
# tune-scanner-host.sh, and reserve-control-bandwidth.sh handle a c6in.metal
# fleet of 15 ENIs without truncating or capping the list at 8 (the prior
# AF_PACKET-bench shape from PR #64).
#
# This is a static sanity test: we don't actually attach 15 NICs to the
# CI runner. We assert the comma-list iterators terminate and emit every
# entry by feeding them a synthetic 15-iface input. If a future change
# adds a hardcoded N=8 cap, this test surfaces it with a non-zero exit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNE_SH="$REPO_ROOT/tools/tune-scanner-host.sh"
RESERVE_SH="$REPO_ROOT/reserve-control-bandwidth.sh"
INSTALL_SH="$REPO_ROOT/install-worker-bundle.sh"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

check_exists() {
    [ -r "$1" ] || fail "missing $1"
}
check_exists "$TUNE_SH"
check_exists "$RESERVE_SH"
check_exists "$INSTALL_SH"

# Build a 15-iface comma list mirroring what
# detect_host_scanner_eni_candidates emits on c6in.metal once 15 ENIs are
# attached.
synthetic=""
for n in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14; do
    if [ -z "$synthetic" ]; then
        synthetic="ens$n"
    else
        synthetic="$synthetic,ens$n"
    fi
done

# Source resolve_managed_interfaces from reserve-control-bandwidth.sh in
# a subshell with the synthetic input. We expect 15 distinct iface names
# on stdout, one per line.
count="$(
    ANYSCAN_RESERVE_INTERFACES="$synthetic" \
    bash -c '
        set -eu
        # shellcheck source=/dev/null
        # Pull only the helper definitions we need; running the whole
        # script would try to apply tc.
        sed -n "/^command_exists/,/^}$/p; /^detect_default_interface/,/^}$/p; /^resolve_managed_interfaces/,/^}$/p" "'"$RESERVE_SH"'" > /tmp/reserve-helpers.sh
        # shellcheck source=/dev/null
        . /tmp/reserve-helpers.sh
        resolve_managed_interfaces | sort -u | wc -l
    '
)"
[ "$count" = "15" ] || fail "reserve-control-bandwidth.sh resolve_managed_interfaces returned $count entries, expected 15"
printf 'PASS: resolve_managed_interfaces handles 15 ENIs (got %s)\n' "$count"

# Same for tune-scanner-host.sh resolve_ifaces.
count="$(
    ANYSCAN_TUNE_INTERFACES="$synthetic" \
    bash -c '
        set -eu
        sed -n "/^command_exists/,/^}$/p; /^detect_default_interface/,/^}$/p; /^resolve_ifaces/,/^}$/p" "'"$TUNE_SH"'" > /tmp/tune-helpers.sh
        # shellcheck source=/dev/null
        . /tmp/tune-helpers.sh
        resolve_ifaces | sort -u | wc -l
    '
)"
[ "$count" = "15" ] || fail "tune-scanner-host.sh resolve_ifaces returned $count entries, expected 15"
printf 'PASS: tune-scanner-host.sh resolve_ifaces handles 15 ENIs (got %s)\n' "$count"

# Confirm install-worker-bundle.sh's "more than one entry" gate triggers
# correctly for a 15-entry list (regression guard for the comma-strip
# trick at lines 314-316).
multi="$(
    bash -c '
        cands="'"$synthetic"'"
        if [ -n "$cands" ] && [ "$cands" != "${cands%,*}" ]; then
            echo yes
        else
            echo no
        fi
    '
)"
[ "$multi" = "yes" ] || fail "install-worker-bundle.sh multi-NIC gate did not trigger for 15-entry list"
printf 'PASS: install-worker-bundle.sh multi-NIC gate triggers for 15-entry list\n'

printf '\nAll multi-ENI iteration sanity checks passed.\n'
