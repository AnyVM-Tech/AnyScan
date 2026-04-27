#!/usr/bin/env bash
# Smoke test for tune-scanner-host.sh
#
# Exercises:
#   - bash -n parses cleanly
#   - --help prints the embedded documentation
#   - dry-run mode emits the expected sysctl/ip-link command sequence
#   - ANYSCAN_TUNE_DISABLE short-circuits cleanly
#   - status mode reports current values without crashing
#   - apply against a temporary sysctl drop-in works end-to-end (skipped
#     unless running as root)
#
# Always exits 0 unless a hard assertion fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/tune-scanner-host.sh"

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

help_check() {
    local out
    out="$("$TARGET_SCRIPT" --help 2>&1)"
    assert_contains "help mentions sysctl" "sysctl" "$out"
    assert_contains "help mentions txqueuelen" "txqueuelen" "$out"
    assert_contains "help mentions reserve-control-bandwidth" "reserve-control-bandwidth.sh" "$out"
}

dry_run_check() {
    # Use a sentinel txqueuelen value the loopback interface is unlikely to
    # already be at, so the "already $target_len" short-circuit doesn't mask
    # the dry-run announcement and cause a flake when this test is rerun
    # after the apply-with-real-drop-in case ran earlier.
    local out
    out="$(ANYSCAN_TUNE_DRY_RUN=true \
        ANYSCAN_TUNE_INTERFACE=lo \
        ANYSCAN_TUNE_TXQUEUELEN=12345 \
        ANYSCAN_TUNE_SYSCTL_FILE=/tmp/anyscan-tune-test.conf \
        "$TARGET_SCRIPT" apply 2>&1)"
    assert_contains "dry-run announces sysctl drop-in" \
        "DRY-RUN: write sysctl drop-in to /tmp/anyscan-tune-test.conf" "$out"
    assert_contains "dry-run announces sysctl -p" \
        "DRY-RUN: sysctl -p /tmp/anyscan-tune-test.conf" "$out"
    assert_contains "dry-run announces ip link txqueuelen" \
        "DRY-RUN: ip link set dev lo txqueuelen 12345" "$out"
    if [ -f /tmp/anyscan-tune-test.conf ]; then
        note_fail "dry-run leaked sysctl file" "/tmp/anyscan-tune-test.conf was created"
        rm -f /tmp/anyscan-tune-test.conf
    else
        note_pass "dry-run did not write sysctl file"
    fi
}

invalid_input_check() {
    local out
    out="$(ANYSCAN_TUNE_DRY_RUN=true \
        ANYSCAN_TUNE_INTERFACE=lo \
        ANYSCAN_TUNE_TXQUEUELEN=banana \
        ANYSCAN_TUNE_LOCAL_PORT_RANGE='not-a-range' \
        "$TARGET_SCRIPT" apply 2>&1)"
    assert_contains "rejects bad txqueuelen" \
        "ANYSCAN_TUNE_TXQUEUELEN=banana invalid; using default 10000" "$out"
    assert_contains "rejects bad port range" \
        "ANYSCAN_TUNE_LOCAL_PORT_RANGE='not-a-range' invalid" "$out"
    # Even with bad inputs the apply should still finish announcing.
    assert_contains "still applies with defaults" "tunings applied" "$out"
}

disable_check() {
    local out
    out="$(ANYSCAN_TUNE_DISABLE=true "$TARGET_SCRIPT" apply 2>&1)"
    assert_contains "disable short-circuits" "ANYSCAN_TUNE_DISABLE is set; skipping" "$out"
    assert_not_contains "disable does not call sysctl" "sysctl -p" "$out"
}

unknown_action_check() {
    local out rc
    out="$("$TARGET_SCRIPT" notarealaction 2>&1)" || true
    rc=$?
    if [ "$rc" -ne 0 ]; then
        note_fail "unknown action exit code" "expected 0, got $rc"
    else
        note_pass "unknown action exits 0"
    fi
    assert_contains "unknown action logs" "unknown action: notarealaction" "$out"
}

status_check() {
    local out
    out="$("$TARGET_SCRIPT" status 2>&1)" || true
    assert_contains "status mentions sysctl drop-in" "sysctl drop-in" "$out"
    assert_contains "status mentions live sysctl values" "live sysctl values" "$out"
}

apply_with_real_dropin() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '  [skip] real apply (not root)\n'
        return 0
    fi
    local tmp original_txqueuelen
    original_txqueuelen="$(cat /sys/class/net/lo/tx_queue_len 2>/dev/null || printf '1000')"
    tmp="$(mktemp /tmp/anyscan-tune-real.XXXXXX.conf)"
    rm -f "$tmp"
    if ANYSCAN_TUNE_INTERFACE=lo \
       ANYSCAN_TUNE_SYSCTL_FILE="$tmp" \
       "$TARGET_SCRIPT" apply >/dev/null 2>&1; then
        if [ -f "$tmp" ]; then
            note_pass "real apply wrote sysctl drop-in"
        else
            note_fail "real apply" "drop-in $tmp missing"
        fi
        if grep -q "net.core.netdev_max_backlog" "$tmp" 2>/dev/null; then
            note_pass "drop-in contains netdev_max_backlog"
        else
            note_fail "drop-in contents" "netdev_max_backlog missing"
        fi
        if ANYSCAN_TUNE_INTERFACE=lo ANYSCAN_TUNE_SYSCTL_FILE="$tmp" "$TARGET_SCRIPT" release >/dev/null 2>&1; then
            if [ ! -f "$tmp" ]; then
                note_pass "release removed drop-in"
            else
                note_fail "release" "drop-in $tmp still present"
                rm -f "$tmp"
            fi
        else
            note_fail "release" "release subcommand failed"
            rm -f "$tmp"
        fi
    else
        note_fail "real apply" "apply subcommand returned non-zero"
        rm -f "$tmp"
    fi
    # Restore loopback txqueuelen so re-running the suite is idempotent.
    ip link set dev lo txqueuelen "$original_txqueuelen" 2>/dev/null || true
}

run_case "bash -n" bash_n_check
run_case "help" help_check
run_case "dry-run apply" dry_run_check
run_case "invalid input" invalid_input_check
run_case "disable" disable_check
run_case "unknown action" unknown_action_check
run_case "status" status_check
run_case "apply with real drop-in" apply_with_real_dropin

printf '\n== summary: %d passed, %d failed ==\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
