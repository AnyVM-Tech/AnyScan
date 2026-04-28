#!/usr/bin/env bash
# Unit test for the ANYSCAN_INSTALL_KERNEL_BACKPORT wire-up in
# install-external-deps.sh (anygpt-44).
#
# Asserts the four paths the operator can hit:
#
#   1. ANYSCAN_INSTALL_KERNEL_BACKPORT unset (default 0) → no apt-get
#      install fires for the backport package; no apt source list is
#      written.
#   2. ANYSCAN_INSTALL_KERNEL_BACKPORT=1 + running kernel already 6.16+ →
#      no apt-get install fires; "already meets" message printed;
#      ena_xdp_zc probe still runs.
#   3. ANYSCAN_INSTALL_KERNEL_BACKPORT=1 + running kernel < 6.16 +
#      apt-get on PATH → apt-get update + apt-get install -t
#      bookworm-backports linux-image-cloud-amd64 fire; the apt source
#      list is written; reboot-required message printed.
#   4. ANYSCAN_INSTALL_KERNEL_BACKPORT=1 + running kernel < 6.16 +
#      apt-get NOT on PATH → graceful skip with note, no apt-get
#      invocations recorded.
#
# Implementation notes:
#   - Stubs `uname`, `apt-get`, `id`, `tee`, `make`, `git`, `ldd`,
#     `readelf` on PATH and records every invocation to per-case logs.
#     `make` writes a synthetic scanner binary so the rest of
#     install-external-deps.sh succeeds end-to-end.
#   - Disables the AF_XDP apt-deps block (ANYSCAN_INSTALL_AFXDP_DEPS=false)
#     so this test only exercises the kernel-backport path.
#   - Redirects the apt sources list path to a per-case temp file so we
#     never touch /etc/apt on the test host.

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

assert_not_contains_substring() {
    local label="$1" needle="$2" file="$3"
    if [ -f "$file" ] && grep -Fq "$needle" "$file"; then
        note_fail "$label" "did not expect substring $(printf '%q' "$needle") in $file"
        sed 's/^/      /' "$file" >&2
    else
        note_pass "$label"
    fi
}

assert_file_missing() {
    local label="$1" file="$2"
    if [ -e "$file" ]; then
        note_fail "$label" "did not expect $file to exist"
    else
        note_pass "$label"
    fi
}

assert_file_present() {
    local label="$1" file="$2"
    if [ -e "$file" ]; then
        note_pass "$label"
    else
        note_fail "$label" "expected $file to exist"
    fi
}

WORK_ROOT="$(mktemp -d)"
KEEP_WORK_ROOT="${KERNEL_BACKPORT_TEST_KEEP_TMP:-0}"
cleanup_work_root() {
    if [ "$KEEP_WORK_ROOT" = "1" ]; then
        printf '[*] WORK_ROOT preserved at %s\n' "$WORK_ROOT" >&2
    else
        rm -rf "$WORK_ROOT"
    fi
}
trap cleanup_work_root EXIT

prepare_stubs() {
    local stub_dir="$1"
    local apt_log="$2"
    local make_log="$3"
    local git_log="$4"
    local uname_release="$5"      # what `uname -r` should print
    local apt_present="$6"        # "yes" → apt-get stub installed; "no" → omitted

    mkdir -p "$stub_dir"

    # Symlink the OS-side essentials install-external-deps.sh needs into
    # stub_dir so the test can run with PATH=$stub_dir only — that lets
    # us drop apt-get from PATH for case 4 without also losing bash /
    # mktemp / install / python3 / etc.
    local cmd resolved
    for cmd in bash env mktemp install sed cat dirname basename \
               python3 printf chmod cp rm mkdir touch ln awk grep sort \
               head tail tr find readlink openssl true false; do
        if resolved="$(command -v "$cmd" 2>/dev/null)"; then
            ln -sf "$resolved" "$stub_dir/$cmd"
        fi
    done

    cat >"$stub_dir/uname" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
    -r) printf '%s\n' "$uname_release" ;;
    -s) printf 'Linux\n' ;;
    -m) printf 'x86_64\n' ;;
    *)  printf 'Linux\n' ;;
esac
EOF
    chmod +x "$stub_dir/uname"

    cat >"$stub_dir/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then
    printf '0\n'
else
    printf 'uid=0(root) gid=0(root) groups=0(root)\n'
fi
EOF
    chmod +x "$stub_dir/id"

    if [ "$apt_present" = "yes" ]; then
        cat >"$stub_dir/apt-get" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$apt_log"
exit 0
EOF
        chmod +x "$stub_dir/apt-get"
    fi

    cat >"$stub_dir/tee" <<'EOF'
#!/usr/bin/env bash
target="${1:-/dev/null}"
cat >"$target"
EOF
    chmod +x "$stub_dir/tee"

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
if [ -n "\$target_dir" ]; then
    mkdir -p "\$target_dir"
    printf '#!/bin/sh\necho stub-scanner\n' >"\$target_dir/scanner"
    chmod +x "\$target_dir/scanner"
fi
exit 0
EOF
    chmod +x "$stub_dir/make"

    cat >"$stub_dir/git" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$git_log"
exit 0
EOF
    chmod +x "$stub_dir/git"

    # Pretend ldd/readelf exist but say nothing about libxdp; the
    # AF_XDP path is gated off in this test (ANYSCAN_USE_AF_XDP unset).
    cat >"$stub_dir/ldd" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$stub_dir/ldd"

    cat >"$stub_dir/readelf" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$stub_dir/readelf"
}

run_install_script() {
    local case_dir="$1"
    local install_kernel_backport="$2"
    local uname_release="$3"
    local apt_present="$4"

    local repo_dir="$case_dir/engine"
    local runtime_env="$case_dir/runtime.env"
    local artifact_dir="$case_dir/artifacts"
    local apt_log="$case_dir/apt-get.log"
    local make_log="$case_dir/make.log"
    local git_log="$case_dir/git.log"
    local stub_dir="$case_dir/stubs"
    local sources_list="$case_dir/anyscan-bookworm-backports.list"

    mkdir -p "$repo_dir" "$artifact_dir"
    : >"$apt_log"
    : >"$make_log"
    : >"$git_log"

    printf 'all:\n\t@true\n' >"$repo_dir/Makefile"
    mkdir -p "$repo_dir/.git"

    prepare_stubs "$stub_dir" "$apt_log" "$make_log" "$git_log" \
        "$uname_release" "$apt_present"

    (
        # PATH = stub_dir only. prepare_stubs symlinks the essentials
        # install-external-deps.sh needs (bash, mktemp, install, sed,
        # python3, ...) into stub_dir, so we get a curated PATH that
        # contains exactly what we want. Whether apt-get is present is
        # controlled by prepare_stubs based on `apt_present` — when "no"
        # the apt-get stub is simply not written and `command -v
        # apt-get` returns false for the install script.
        export PATH="$stub_dir"
        export ANYSCAN_INSTALL_KERNEL_BACKPORT="$install_kernel_backport"
        export ANYSCAN_KERNEL_BACKPORT_SOURCES_LIST="$sources_list"
        export ANYSCAN_VULNSCANNER_REPO_DIR="$repo_dir"
        export ANYSCAN_INSTALL_AFXDP_DEPS=false
        export ANYSCAN_USE_AF_XDP=0
        export ANYSCAN_RUNTIME_ENV_FILE="$runtime_env"
        export ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR="$artifact_dir"
        unset SUDO_USER
        "$TARGET_SCRIPT" >"$case_dir/stdout.log" 2>"$case_dir/stderr.log"
    )
}

# ---------------------------------------------------------------------------
# Case 1: knob unset → no apt-get install for backport, no source list.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-default-off"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "0" "6.12.74" "yes"; then
    note_pass "default (knob=0) build runs successfully"
    assert_not_contains_substring \
        "default (knob=0): no apt-get install for backport package" \
        "linux-image-cloud-amd64" \
        "$case_dir/apt-get.log"
    assert_not_contains_substring \
        "default (knob=0): no apt-get update for backports suite" \
        "bookworm-backports" \
        "$case_dir/apt-get.log"
    assert_file_missing \
        "default (knob=0): apt source list NOT created" \
        "$case_dir/anyscan-bookworm-backports.list"
else
    note_fail "default (knob=0) build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 2: knob=1 + kernel 6.16 already → skip install but probe ena_xdp_zc.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-already-new-enough"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "6.16.0-cloud-amd64" "yes"; then
    note_pass "knob=1 + kernel 6.16 build runs successfully"
    assert_not_contains_substring \
        "knob=1 + kernel 6.16: no apt-get install for backport" \
        "linux-image-cloud-amd64" \
        "$case_dir/apt-get.log"
    assert_contains_substring \
        "knob=1 + kernel 6.16: 'already meets' message printed" \
        "already meets" \
        "$case_dir/stdout.log"
    assert_file_missing \
        "knob=1 + kernel 6.16: apt source list NOT created" \
        "$case_dir/anyscan-bookworm-backports.list"
else
    note_fail "knob=1 + kernel 6.16 build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 3: knob=1 + kernel 6.12 + apt-get available → install fires.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-install-backport"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "6.12.74-cloud-amd64" "yes"; then
    note_pass "knob=1 + kernel 6.12 build runs successfully"
    assert_contains_substring \
        "knob=1 + kernel 6.12: apt-get update fires" \
        "update" \
        "$case_dir/apt-get.log"
    assert_contains_substring \
        "knob=1 + kernel 6.12: apt-get install -t bookworm-backports fires" \
        "install -y --no-install-recommends -t bookworm-backports linux-image-cloud-amd64" \
        "$case_dir/apt-get.log"
    assert_contains_substring \
        "knob=1 + kernel 6.12: REBOOT REQUIRED notice printed" \
        "REBOOT REQUIRED" \
        "$case_dir/stdout.log"
    assert_file_present \
        "knob=1 + kernel 6.12: apt source list created" \
        "$case_dir/anyscan-bookworm-backports.list"
    assert_contains_substring \
        "knob=1 + kernel 6.12: apt source list points at bookworm-backports" \
        "bookworm-backports" \
        "$case_dir/anyscan-bookworm-backports.list"
else
    note_fail "knob=1 + kernel 6.12 build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

# ---------------------------------------------------------------------------
# Case 4: knob=1 + kernel 6.12 + apt-get NOT on PATH → graceful skip.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-no-apt"
mkdir -p "$case_dir"
if run_install_script "$case_dir" "1" "6.12.74-cloud-amd64" "no"; then
    note_pass "knob=1 + no apt-get build runs successfully"
    if [ -s "$case_dir/apt-get.log" ]; then
        note_fail "knob=1 + no apt-get: no apt-get invocations recorded" \
            "expected empty apt-get.log but got: $(tr '\n' '|' <"$case_dir/apt-get.log")"
    else
        note_pass "knob=1 + no apt-get: no apt-get invocations recorded"
    fi
    assert_contains_substring \
        "knob=1 + no apt-get: 'apt-get not on PATH' note printed" \
        "apt-get not on PATH" \
        "$case_dir/stdout.log"
    assert_file_missing \
        "knob=1 + no apt-get: apt source list NOT created" \
        "$case_dir/anyscan-bookworm-backports.list"
else
    note_fail "knob=1 + no apt-get build" "install-external-deps.sh exited non-zero (see $case_dir/stderr.log)"
fi

printf '\n'
printf 'PASS: %d\n' "$PASS"
printf 'FAIL: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
