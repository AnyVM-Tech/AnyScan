#!/usr/bin/env bash
# Unit test for the PF_RING ZC build wire-up in install-external-deps.sh
# (anygpt-46). Mirror of tools/test-install-external-deps-afxdp.sh.
#
# Asserts that install-external-deps.sh forwards ANYSCAN_USE_PFRING_ZC
# through to the engine's `make` invocation:
#
#   1. ANYSCAN_USE_PFRING_ZC=0 (default) → `make` is called with NO
#      USE_PFRING_ZC=1 token. Existing AMIs keep building the legacy
#      AF_PACKET-only binary.
#   2. ANYSCAN_USE_PFRING_ZC=1 + missing scanner → `make USE_PFRING_ZC=1`.
#   3. ANYSCAN_USE_PFRING_ZC=1 + cached AF_PACKET-only binary → cache
#      check detects missing libpfring linkage and force-rebuilds via
#      `make clean` + `make USE_PFRING_ZC=1`.
#   4. ANYSCAN_USE_PFRING_ZC=1 + cached PFRING-ZC-linked binary → no rebuild.
#
# Implementation notes:
#   - Stubs `make`, `git`, `ldd`, `readelf` on PATH and records every
#     invocation. `git fetch/pull` becomes a no-op so we don't hit the
#     network; `make` writes a synthetic scanner binary whose libpfring
#     linkage is controlled by the test (presence of $linkage_marker).
#   - Disables both the AF_XDP and PF_RING ZC apt-deps blocks so we don't
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

    # `make` stub: append every argv to make_log and produce a fake scanner
    # binary at $1/scanner when the first arg is `-C <dir>`. The caller
    # decides whether the synthetic binary "has" libpfring linkage by
    # touching $linkage_marker before running.
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
    # Pretend this build linked libpfring.
    printf '#!/bin/sh\necho stub-scanner-with-pfring\n' >"\$target_dir/scanner"
    printf 'libpfring-marker\n' >"\$target_dir/scanner.linkage"
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

    # `ldd` stub: return a libpfring.so line iff <bin>.linkage contains
    # 'libpfring-marker'. The real ldd walks NEEDED entries; the marker is
    # set by the make stub above so the test controls which builds appear
    # PFRING-ZC-linked.
    cat >"$stub_dir/ldd" <<'EOF'
#!/usr/bin/env bash
bin="$1"
if [ -f "${bin}.linkage" ] && grep -q libpfring-marker "${bin}.linkage"; then
    printf '\tlibpfring.so.8 => /usr/lib/x86_64-linux-gnu/libpfring.so.8 (0x00007f00)\n'
fi
exit 0
EOF
    chmod +x "$stub_dir/ldd"

    # `readelf` stub: only consulted when ldd is missing. Mirrors the ldd
    # logic so the test still covers the readelf branch when ldd is
    # removed from PATH.
    cat >"$stub_dir/readelf" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-d" ]; then
    bin="$2"
    if [ -f "${bin}.linkage" ] && grep -q libpfring-marker "${bin}.linkage"; then
        printf ' 0x0000000000000001 (NEEDED)             Shared library: [libpfring.so.8]\n'
    fi
fi
exit 0
EOF
    chmod +x "$stub_dir/readelf"
}

run_install_script() {
    local case_dir="$1"
    local use_pfring_zc="$2"
    local linkage_marker_state="$3"   # "pfring" or "legacy" or "missing"

    local repo_dir="$case_dir/engine"
    local runtime_env="$case_dir/runtime.env"
    local artifact_dir="$case_dir/artifacts"
    local make_log="$case_dir/make.log"
    local git_log="$case_dir/git.log"
    local stub_dir="$case_dir/stubs"
    local linkage_marker="$case_dir/linkage_is_pfring"

    mkdir -p "$repo_dir" "$artifact_dir"
    : >"$make_log"
    : >"$git_log"
    rm -f "$linkage_marker"

    printf 'all:\n\t@true\n' >"$repo_dir/Makefile"
    mkdir -p "$repo_dir/.git"

    case "$linkage_marker_state" in
        pfring)
            printf '#!/bin/sh\necho cached-scanner-pfring\n' >"$repo_dir/scanner"
            printf 'libpfring-marker\n' >"$repo_dir/scanner.linkage"
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

    # The `make` stub uses linkage_marker presence to decide what the
    # NEW binary will look like. For the "force rebuild" test we want
    # the rebuilt binary to be PFRING-ZC-linked even though the cached
    # one was legacy.
    if [ "$use_pfring_zc" = "1" ]; then
        : >"$linkage_marker"
    fi

    prepare_stubs "$stub_dir" "$make_log" "$git_log" "$linkage_marker"

    (
        export PATH="$stub_dir:$PATH"
        export ANYSCAN_USE_PFRING_ZC="$use_pfring_zc"
        export ANYSCAN_VULNSCANNER_REPO_DIR="$repo_dir"
        export ANYSCAN_INSTALL_AFXDP_DEPS=false
        export ANYSCAN_INSTALL_PFRING_ZC_DEPS=false
        export ANYSCAN_RUNTIME_ENV_FILE="$runtime_env"
        export ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR="$artifact_dir"
        unset SUDO_USER
        "$TARGET_SCRIPT" >"$case_dir/stdout.log" 2>"$case_dir/stderr.log"
    )
}

# ---------------------------------------------------------------------------
# Case 1: ANYSCAN_USE_PFRING_ZC unset → no USE_PFRING_ZC=1 in make argv.
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
        "default build does NOT pass USE_PFRING_ZC=1" \
        "USE_PFRING_ZC=1" \
        "$case_dir/make.log"
else
    note_fail "default build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 2: ANYSCAN_USE_PFRING_ZC=1 + no cached binary → make USE_PFRING_ZC=1.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-pfring-fresh"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "missing"; then
    note_pass "pfring fresh build runs successfully"
    assert_contains_substring \
        "pfring fresh build passes USE_PFRING_ZC=1 to make" \
        "USE_PFRING_ZC=1" \
        "$case_dir/make.log"
else
    note_fail "pfring fresh build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 3: ANYSCAN_USE_PFRING_ZC=1 + cached AF_PACKET-only binary → force rebuild
#         via make clean + make USE_PFRING_ZC=1.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-pfring-force"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "legacy"; then
    note_pass "pfring force-rebuild runs successfully"
    assert_contains_substring \
        "pfring force-rebuild invokes make clean" \
        "clean" \
        "$case_dir/make.log"
    assert_contains_substring \
        "pfring force-rebuild passes USE_PFRING_ZC=1 to make" \
        "USE_PFRING_ZC=1" \
        "$case_dir/make.log"
else
    note_fail "pfring force-rebuild" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 4: ANYSCAN_USE_PFRING_ZC=1 + cached PFRING-ZC-linked binary → no rebuild.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-pfring-cached"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "pfring"; then
    note_pass "pfring cached-binary path runs successfully"
    if [ -s "$case_dir/make.log" ]; then
        note_fail "pfring cached-binary path skips make" \
            "expected empty make.log but got: $(tr '\n' '|' <"$case_dir/make.log")"
    else
        note_pass "pfring cached-binary path skips make"
    fi
else
    note_fail "pfring cached-binary path" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

printf '\n'
printf 'PASS: %d\n' "$PASS"
printf 'FAIL: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
