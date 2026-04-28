#!/usr/bin/env bash
# Unit test for the DPDK build wire-up in install-external-deps.sh
# (plans/2026-04-28-portscan-dpdk-impl-v1.md §3.10.1).
#
# Asserts that install-external-deps.sh forwards ANYSCAN_USE_DPDK through
# to the engine's `make` invocation, mirroring the AF_XDP shape of
# tools/test-install-external-deps-afxdp.sh:
#
#   1. ANYSCAN_USE_DPDK=0 (default) → `make` is called with NO USE_DPDK=1
#      token. Existing AMIs keep building the legacy AF_PACKET-only binary.
#   2. ANYSCAN_USE_DPDK=1 + missing scanner → `make USE_DPDK=1`.
#   3. ANYSCAN_USE_DPDK=1 + cached non-DPDK binary → cache check detects
#      missing librte_eal linkage and force-rebuilds via `make clean` +
#      `make USE_DPDK=1`.
#   4. ANYSCAN_USE_DPDK=1 + cached DPDK-linked binary → no rebuild.
#
# Implementation notes:
#   - Stubs `make`, `git`, `ldd`, `readelf` on PATH and records every
#     invocation. `git fetch/pull` is a no-op so we don't hit the network;
#     `make` writes a synthetic scanner binary whose librte_eal linkage is
#     controlled by the test (env STUB_MAKE_PRODUCES_DPDK).
#   - Disables the DPDK / AF_XDP / PF_RING apt-deps blocks so we don't
#     probe sudo on CI hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/../install-external-deps.sh"

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

assert_contains_line() {
    local label="$1" expected="$2" file="$3"
    if [ -f "$file" ] && grep -Fxq -- "$expected" "$file"; then
        note_pass "$label"
    else
        note_fail "$label" "expected line $(printf '%q' "$expected") in $file"
        if [ -f "$file" ]; then
            printf '    file contents:\n' >&2
            sed 's/^/      /' "$file" >&2
        fi
    fi
}

assert_not_contains_substring() {
    local label="$1" needle="$2" file="$3"
    if [ -f "$file" ] && grep -Fq "$needle" "$file"; then
        note_fail "$label" "did not expect substring $(printf '%q' "$needle") in $file"
        sed 's/^/      /' "$file" >&2
    else
        note_pass "$label"
    fi
}

assert_contains_substring() {
    local label="$1" needle="$2" file="$3"
    if [ -f "$file" ] && grep -Fq "$needle" "$file"; then
        note_pass "$label"
    else
        note_fail "$label" "expected substring $(printf '%q' "$needle") in $file"
        if [ -f "$file" ]; then
            sed 's/^/      /' "$file" >&2
        fi
    fi
}

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

prepare_stubs() {
    local stub_dir="$1"
    local make_log="$2"
    local git_log="$3"
    local linkage_marker="$4"

    mkdir -p "$stub_dir"

    cat >"$stub_dir/make" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$make_log"
target_dir=""
i=0
while [ \$i -lt \$# ]; do
    i=\$(( i + 1 ))
    arg="\${!i}"
    if [ "\$arg" = "-C" ]; then
        i=\$(( i + 1 ))
        target_dir="\${!i}"
    fi
done
clean_only=0
for arg in "\$@"; do
    if [ "\$arg" = "clean" ]; then
        clean_only=1
        break
    fi
done
if [ "\$clean_only" = "1" ]; then
    if [ -n "\$target_dir" ]; then
        rm -f "\$target_dir/scanner"
    fi
    exit 0
fi
if [ -z "\$target_dir" ]; then
    exit 0
fi
mkdir -p "\$target_dir"
if [ -f "$linkage_marker" ]; then
    # Pretend this build linked librte_eal.
    printf '#!/bin/sh\necho stub-scanner-with-dpdk\n' >"\$target_dir/scanner"
    printf 'librte_eal-marker\n' >"\$target_dir/scanner.linkage"
else
    printf '#!/bin/sh\necho stub-scanner\n' >"\$target_dir/scanner"
    : >"\$target_dir/scanner.linkage"
fi
chmod +x "\$target_dir/scanner"
EOF
    chmod +x "$stub_dir/make"

    cat >"$stub_dir/git" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$git_log"
exit 0
EOF
    chmod +x "$stub_dir/git"

    # `ldd` stub: return a librte_eal.so line iff <bin>.linkage contains
    # 'librte_eal-marker'. The real ldd walks NEEDED entries; the marker
    # is set by the make stub above so the test controls which builds
    # appear DPDK-linked.
    cat >"$stub_dir/ldd" <<'EOF'
#!/usr/bin/env bash
bin="$1"
if [ -f "${bin}.linkage" ] && grep -q librte_eal-marker "${bin}.linkage"; then
    printf '\tlibrte_eal.so.24 => /usr/lib/x86_64-linux-gnu/librte_eal.so.24 (0x00007f00)\n'
fi
exit 0
EOF
    chmod +x "$stub_dir/ldd"

    cat >"$stub_dir/readelf" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-d" ]; then
    bin="$2"
    if [ -f "${bin}.linkage" ] && grep -q librte_eal-marker "${bin}.linkage"; then
        printf ' 0x0000000000000001 (NEEDED)             Shared library: [librte_eal.so.24]\n'
    fi
fi
exit 0
EOF
    chmod +x "$stub_dir/readelf"
}

run_install_script() {
    local case_dir="$1"
    local use_dpdk="$2"
    local linkage_marker_state="$3"   # "dpdk" or "legacy" or "missing"

    local repo_dir="$case_dir/engine"
    local runtime_env="$case_dir/runtime.env"
    local artifact_dir="$case_dir/artifacts"
    local make_log="$case_dir/make.log"
    local git_log="$case_dir/git.log"
    local stub_dir="$case_dir/stubs"
    local linkage_marker="$case_dir/linkage_is_dpdk"

    mkdir -p "$repo_dir" "$artifact_dir"
    : >"$make_log"
    : >"$git_log"
    rm -f "$linkage_marker"

    printf 'all:\n\t@true\n' >"$repo_dir/Makefile"
    mkdir -p "$repo_dir/.git"

    case "$linkage_marker_state" in
        dpdk)
            printf '#!/bin/sh\necho cached-scanner-dpdk\n' >"$repo_dir/scanner"
            printf 'librte_eal-marker\n' >"$repo_dir/scanner.linkage"
            chmod +x "$repo_dir/scanner"
            ;;
        legacy)
            printf '#!/bin/sh\necho cached-scanner-legacy\n' >"$repo_dir/scanner"
            : >"$repo_dir/scanner.linkage"
            chmod +x "$repo_dir/scanner"
            ;;
        missing)
            : ;;
        *)
            printf '[!] unknown linkage marker state %s\n' "$linkage_marker_state" >&2
            exit 1
            ;;
    esac

    if [ "$use_dpdk" = "1" ]; then
        : >"$linkage_marker"
    fi

    prepare_stubs "$stub_dir" "$make_log" "$git_log" "$linkage_marker"

    (
        export PATH="$stub_dir:$PATH"
        export ANYSCAN_USE_DPDK="$use_dpdk"
        export ANYSCAN_VULNSCANNER_REPO_DIR="$repo_dir"
        export ANYSCAN_INSTALL_DPDK_DEPS=false
        export ANYSCAN_INSTALL_AFXDP_DEPS=false
        export ANYSCAN_INSTALL_PFRING_ZC_DEPS=false
        export ANYSCAN_RUNTIME_ENV_FILE="$runtime_env"
        export ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR="$artifact_dir"
        unset SUDO_USER
        "$TARGET_SCRIPT" >"$case_dir/stdout.log" 2>"$case_dir/stderr.log"
    )
}

# ---------------------------------------------------------------------------
# Case 1: ANYSCAN_USE_DPDK unset → no USE_DPDK=1 in make argv.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-default"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "0" "missing"; then
    note_pass "default build runs successfully"
    assert_contains_line \
        "default build calls make with engine repo only" \
        "-C $case_dir/engine" \
        "$case_dir/make.log"
    assert_not_contains_substring \
        "default build does NOT pass USE_DPDK=1" \
        "USE_DPDK=1" \
        "$case_dir/make.log"
else
    note_fail "default build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 2: ANYSCAN_USE_DPDK=1 + no cached binary → make USE_DPDK=1.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-dpdk-fresh"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "missing"; then
    note_pass "dpdk fresh build runs successfully"
    assert_contains_substring \
        "dpdk fresh build passes USE_DPDK=1 to make" \
        "USE_DPDK=1" \
        "$case_dir/make.log"
else
    note_fail "dpdk fresh build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 3: ANYSCAN_USE_DPDK=1 + cached AF_PACKET-only binary → force rebuild
#         via make clean + make USE_DPDK=1.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-dpdk-force"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "legacy"; then
    note_pass "dpdk force-rebuild runs successfully"
    assert_contains_substring \
        "dpdk force-rebuild invokes make clean" \
        "clean" \
        "$case_dir/make.log"
    assert_contains_substring \
        "dpdk force-rebuild passes USE_DPDK=1 to make" \
        "USE_DPDK=1" \
        "$case_dir/make.log"
else
    note_fail "dpdk force-rebuild" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 4: ANYSCAN_USE_DPDK=1 + cached DPDK-linked binary → no rebuild.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-dpdk-cached"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "dpdk"; then
    note_pass "dpdk cached-binary path runs successfully"
    if [ -s "$case_dir/make.log" ]; then
        note_fail "dpdk cached-binary path skips make" \
            "expected empty make.log but got: $(tr '\n' '|' <"$case_dir/make.log")"
    else
        note_pass "dpdk cached-binary path skips make"
    fi
else
    note_fail "dpdk cached-binary path" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

printf '\n'
printf 'PASS: %d\n' "$PASS"
printf 'FAIL: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
