#!/usr/bin/env bash
# Smoke test for reserve-control-bandwidth.sh
#
# Exercises:
#   - dry-run mode emits the expected tc command sequence
#   - --help prints the embedded documentation
#   - ANYSCAN_RESERVE_DISABLE short-circuits cleanly
#   - apply against a temporary dummy interface installs and tears down
#     a real HTB qdisc (skipped if not running as root or `tc`/`ip` are
#     unavailable)
#
# Always exits 0 unless a hard assertion fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/../reserve-control-bandwidth.sh"

if [ ! -x "$TARGET_SCRIPT" ]; then
    printf '[!] %s is not executable\n' "$TARGET_SCRIPT" >&2
    exit 1
fi

PASS=0
FAIL=0

note_pass() {
    PASS=$(( PASS + 1 ))
    printf '  [ok] %s\n' "$1"
}

note_fail() {
    FAIL=$(( FAIL + 1 ))
    printf '  [FAIL] %s: %s\n' "$1" "$2" >&2
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        note_pass "$label"
    else
        note_fail "$label" "expected to find $needle"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        note_fail "$label" "did not expect to find $needle"
    else
        note_pass "$label"
    fi
}

run_case() {
    local label="$1"
    shift
    printf '\n== %s ==\n' "$label"
    "$@"
}

bash_n_check() {
    bash -n "$TARGET_SCRIPT"
    note_pass "bash -n on $TARGET_SCRIPT"
}

dry_run_check() {
    local out
    out="$(ANYSCAN_RESERVE_DRY_RUN=true \
        ANYSCAN_RESERVE_INTERFACE=eth0-test \
        ANYSCAN_CONTROL_PLANE_HOST=10.0.0.1 \
        ANYSCAN_RESERVE_BANDWIDTH_BPS=5000000 \
        ANYSCAN_RESERVE_LINK_RATE_BPS=1000000000 \
        bash "$TARGET_SCRIPT" apply 2>&1)"

    assert_contains "dry-run announces interface" "applying egress reservation on eth0-test" "$out"
    assert_contains "dry-run installs root htb qdisc" \
        "tc qdisc add dev eth0-test root handle 1: htb default 20" "$out"
    assert_contains "dry-run installs reserve class" \
        "classid 1:10 htb rate 5000000bit" "$out"
    assert_contains "dry-run installs bulk class" \
        "classid 1:20" "$out"
}

disable_check() {
    local out
    out="$(ANYSCAN_RESERVE_DISABLE=true bash "$TARGET_SCRIPT" apply 2>&1)"
    assert_contains "disable env short-circuits" "ANYSCAN_RESERVE_DISABLE is set" "$out"
    assert_not_contains "disable env emits no qdisc command" "tc qdisc add" "$out"
}

help_check() {
    local out
    out="$(bash "$TARGET_SCRIPT" --help 2>&1)"
    assert_contains "help mentions HTB qdisc" "HTB qdisc" "$out"
    assert_contains "help mentions ANYSCAN_RESERVE_BANDWIDTH_BPS" \
        "ANYSCAN_RESERVE_BANDWIDTH_BPS" "$out"
}

invalid_action_check() {
    local out
    out="$(bash "$TARGET_SCRIPT" not-an-action 2>&1)"
    assert_contains "invalid action is logged" "unknown action: not-an-action" "$out"
}

real_interface_check() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '  [skip] not root; skipping live tc test\n'
        return 0
    fi
    if ! command -v ip >/dev/null 2>&1 || ! command -v tc >/dev/null 2>&1; then
        printf '  [skip] ip(8) or tc(8) missing; skipping live tc test\n'
        return 0
    fi
    # Linux iface names are limited to IFNAMSIZ-1 = 15 chars.
    local iface=anyscan-bw-tst
    if ! ip link add dev "$iface" type dummy >/dev/null 2>&1; then
        printf '  [skip] cannot create dummy interface (no kernel module?); skipping\n'
        return 0
    fi
    cleanup_iface() {
        ip link delete "$1" >/dev/null 2>&1 || true
    }
    local out_apply out_status out_release
    out_apply="$(ANYSCAN_RESERVE_INTERFACE="$iface" \
        ANYSCAN_RESERVE_BANDWIDTH_BPS=5000000 \
        ANYSCAN_RESERVE_LINK_RATE_BPS=100000000 \
        bash "$TARGET_SCRIPT" apply 2>&1)"
    assert_contains "live apply announces" "reservation active on $iface" "$out_apply"
    out_status="$(tc -s class show dev "$iface" 2>&1)"
    assert_contains "live apply created class 1:10" "class htb 1:10" "$out_status"
    assert_contains "live apply created class 1:20" "class htb 1:20" "$out_status"
    out_release="$(ANYSCAN_RESERVE_INTERFACE="$iface" \
        bash "$TARGET_SCRIPT" release 2>&1)"
    assert_contains "live release tears down" "released reservation on $iface" "$out_release"
    out_status="$(tc qdisc show dev "$iface" 2>&1)"
    assert_not_contains "live release removed htb qdisc" "qdisc htb 1:" "$out_status"
    cleanup_iface "$iface"
}

run_case "syntax check" bash_n_check
run_case "dry-run apply" dry_run_check
run_case "disable env" disable_check
run_case "help output" help_check
run_case "invalid action" invalid_action_check
run_case "live tc apply/release" real_interface_check

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
