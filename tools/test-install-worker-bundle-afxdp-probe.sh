#!/usr/bin/env bash
# Unit tests for install-worker-bundle.sh::probe_afxdp_runtime_available
# and parse_kernel_major_minor.
#
# anygpt-52 (PR #65 issuecomment-4339242358) reported the probe
# returning false on c6in.metal Debian 13 + kernel 6.12.74 — claiming
# "kernel <5.10 or libxdp.so missing" when the kernel was clearly 6.12
# and libxdp1 was on the host. The fix uses awk -F'[.-]' so the parser
# robustly handles 3-component releases with suffixes like:
#
#   6.12.74-cloud-amd64
#   5.10.0-13-amd64
#   6.12.74+deb13+1-amd64
#   5.4.282-rt
#
# These tests exercise:
#   1. parse_kernel_major_minor on the full set of release shapes we've
#      seen in the wild + a couple of edge cases.
#   2. probe_afxdp_runtime_available with a stubbed `uname` and `ldconfig`
#      to assert the four return paths:
#        - kernel < 5.10 → false
#        - kernel >= 5.10 + libxdp.so missing → false
#        - kernel >= 5.10 + libxdp.so present → true
#        - unparseable kernel → false
#   3. The probe stderr carries a single-line reason on failure so the
#      operator can tell which check failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/../install-worker-bundle.sh"

if [ ! -r "$TARGET_SCRIPT" ]; then
    printf '[!] %s not found\n' "$TARGET_SCRIPT" >&2
    exit 1
fi

PASS=0
FAIL=0

note_pass() { PASS=$(( PASS + 1 )); printf '  [ok] %s\n' "$1"; }
note_fail() { FAIL=$(( FAIL + 1 )); printf '  [FAIL] %s: %s\n' "$1" "$2" >&2; }

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        note_pass "$label"
    else
        note_fail "$label" "expected $(printf '%q' "$expected") got $(printf '%q' "$actual")"
    fi
}

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

# Source the script with the load-only hook so main() is skipped. Puts
# parse_kernel_major_minor + probe_afxdp_runtime_available in scope.
load_script() {
    # shellcheck disable=SC1090
    export ANYSCAN_INSTALL_LOAD_ONLY=1
    source "$TARGET_SCRIPT"
}

# ---------------------------------------------------------------------------
# parse_kernel_major_minor: cover every release shape we've shipped on.
# Each subshell isolates the sourced state so failures don't cascade.
# ---------------------------------------------------------------------------
test_parse() {
    local release="$1" expected="$2"
    local actual
    actual="$(
        load_script
        parse_kernel_major_minor "$release"
    )"
    assert_eq "parse_kernel_major_minor $(printf '%q' "$release") → $(printf '%q' "$expected")" \
        "$expected" "$actual"
}

test_parse "6.12.74+deb13+1-amd64"  "6 12"
test_parse "6.12.74-cloud-amd64"    "6 12"
test_parse "5.10.0-13-amd64"        "5 10"
test_parse "5.4.282-rt"             "5 4"
test_parse "4.19.276-amd64"         "4 19"
test_parse "5.10"                   "5 10"
test_parse "5"                      "5 0"
test_parse ""                       "0 0"

# ---------------------------------------------------------------------------
# probe_afxdp_runtime_available with stubbed uname / ldconfig.
# ---------------------------------------------------------------------------
make_stubs() {
    local stub_dir="$1" uname_release="$2" libxdp_present="$3"

    mkdir -p "$stub_dir"

    cat >"$stub_dir/uname" <<EOF
#!/usr/bin/env bash
if [ "\$1" = "-r" ]; then
    printf '%s\n' "$uname_release"
    exit 0
fi
exec /usr/bin/uname "\$@"
EOF
    chmod +x "$stub_dir/uname"

    if [ "$libxdp_present" = "true" ]; then
        cat >"$stub_dir/ldconfig" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-p" ]; then
    cat <<LD
        libxdp.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libxdp.so.1
        libxdp.so (libc6,x86-64) => /lib/x86_64-linux-gnu/libxdp.so
LD
    exit 0
fi
exit 0
EOF
    else
        cat >"$stub_dir/ldconfig" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-p" ]; then
    cat <<'LD'
        libc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6
LD
    exit 0
fi
exit 0
EOF
    fi
    chmod +x "$stub_dir/ldconfig"
}

test_probe() {
    local label="$1" uname_release="$2" libxdp_present="$3" expected_value="$4" expected_stderr_contains="$5"

    local case_dir="$WORK_ROOT/$(echo "$label" | tr ' /' '__')"
    mkdir -p "$case_dir"
    local stub_dir="$case_dir/stubs"
    make_stubs "$stub_dir" "$uname_release" "$libxdp_present"

    local stdout_file="$case_dir/probe.stdout"
    local stderr_file="$case_dir/probe.stderr"

    (
        export PATH="$stub_dir:$PATH"
        load_script
        probe_afxdp_runtime_available
    ) >"$stdout_file" 2>"$stderr_file"

    local actual
    actual="$(cat "$stdout_file")"
    assert_eq "probe ($label) → $(printf '%q' "$expected_value")" \
        "$expected_value" "$actual"

    if [ -n "$expected_stderr_contains" ]; then
        if grep -Fq -- "$expected_stderr_contains" "$stderr_file"; then
            note_pass "probe ($label) stderr contains $(printf '%q' "$expected_stderr_contains")"
        else
            note_fail "probe ($label) stderr contains $(printf '%q' "$expected_stderr_contains")" \
                "stderr was: $(cat "$stderr_file")"
        fi
    fi
}

# Bug 5 repro: 6.12.74 + libxdp present must return true. The OLD
# parameter-expansion parser claimed kernel <5.10 here.
test_probe "c6in.metal Debian 13 6.12.74 + libxdp" \
    "6.12.74+deb13+1-amd64" "true" \
    "true" ""

# 6.12 with no libxdp → false, stderr names the missing library.
test_probe "kernel 6.12 + libxdp missing" \
    "6.12.74-cloud-amd64" "false" \
    "false" "libxdp.so not in ldconfig"

# Old kernel (4.19) → false, stderr names the version.
test_probe "kernel 4.19 too old" \
    "4.19.276-amd64" "true" \
    "false" "kernel 4.19 < 5.10"

# 5.10 boundary: 5.9 → false, 5.10 → true, 5.11 → true.
test_probe "kernel 5.9 too old" \
    "5.9.0-amd64" "true" \
    "false" "kernel 5.9 < 5.10"
test_probe "kernel 5.10 boundary" \
    "5.10.0-amd64" "true" \
    "true" ""
test_probe "kernel 5.11 above boundary" \
    "5.11.0-amd64" "true" \
    "true" ""

# Empty uname → false, stderr says could not parse.
test_probe "empty uname output" \
    "" "true" \
    "false" "could not parse kernel"

# Unparseable uname (no leading digit) → false, stderr says could not parse.
test_probe "non-numeric uname" \
    "linux-custom-build" "true" \
    "false" "could not parse kernel"

printf '\n'
printf 'PASS: %d\n' "$PASS"
printf 'FAIL: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
