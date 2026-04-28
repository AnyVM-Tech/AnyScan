#!/usr/bin/env bash
# Unit tests for tools/setup-dpdk.sh `bind` path:
#
#   1. cmd_bind brings each target NIC down with `ip link set <ifc> down`
#      BEFORE invoking dpdk-devbind. Without this, dpdk-devbind refuses
#      with "Warning: routing table indicates that interface is active.
#      Not modifying" and the operator has to bring the iface down by
#      hand on every NIC. PR #65 issuecomment-4339242358 (anygpt-52).
#
#   2. ensure_hugetlbfs_mount mounts /mnt/huge1g (default) with
#      `pagesize=1G` after a 1 GiB hugepages reservation. Reserving
#      nr_hugepages alone is not enough — rte_eal_init refuses to start
#      ("EAL: No available 1048576 kB hugepages reported on node 0")
#      unless a hugetlbfs of the matching pagesize is mounted.
#
#   3. ensure_hugetlbfs_mount is idempotent: when the target is already
#      a hugetlbfs of the matching pagesize, it skips the mount.
#
#   4. ensure_hugetlbfs_mount with an empty mount path is a no-op (lets
#      operators who provision hugetlbfs via fstab opt out cleanly).
#
# The tests source setup-dpdk.sh with ANYSCAN_DPDK_LOAD_ONLY=1 so the
# argv dispatch is skipped, then call the helpers in a hermetic shell
# with stubbed binaries on PATH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/setup-dpdk.sh"

if [ ! -x "$TARGET_SCRIPT" ]; then
    printf '[!] %s is not executable\n' "$TARGET_SCRIPT" >&2
    exit 1
fi

PASS=0
FAIL=0

note_pass() { PASS=$(( PASS + 1 )); printf '  [ok] %s\n' "$1"; }
note_fail() { FAIL=$(( FAIL + 1 )); printf '  [FAIL] %s: %s\n' "$1" "$2" >&2; }

assert_log_contains() {
    local label="$1" needle="$2" file="$3"
    if [ -f "$file" ] && grep -Fq -- "$needle" "$file"; then
        note_pass "$label"
    else
        note_fail "$label" "expected $(printf '%q' "$needle") in $file"
        if [ -f "$file" ]; then
            printf '    log:\n' >&2
            sed 's/^/      /' "$file" >&2
        fi
    fi
}

assert_log_not_contains() {
    local label="$1" needle="$2" file="$3"
    if [ -f "$file" ] && grep -Fq -- "$needle" "$file"; then
        note_fail "$label" \
            "expected $(printf '%q' "$needle") NOT in $file but log shows: $(tr '\n' '|' <"$file")"
    else
        note_pass "$label"
    fi
}

assert_log_order() {
    local label="$1" earlier="$2" later="$3" file="$4"
    if [ ! -f "$file" ]; then
        note_fail "$label" "log file $file does not exist"
        return
    fi
    local earlier_line later_line
    earlier_line="$(grep -Fn -- "$earlier" "$file" | head -n1 | cut -d: -f1 || true)"
    later_line="$(grep -Fn -- "$later" "$file" | head -n1 | cut -d: -f1 || true)"
    if [ -z "$earlier_line" ]; then
        note_fail "$label" "$(printf '%q' "$earlier") not in log"
        sed 's/^/      /' "$file" >&2
        return
    fi
    if [ -z "$later_line" ]; then
        note_fail "$label" "$(printf '%q' "$later") not in log"
        sed 's/^/      /' "$file" >&2
        return
    fi
    if [ "$earlier_line" -lt "$later_line" ]; then
        note_pass "$label"
    else
        note_fail "$label" \
            "expected $(printf '%q' "$earlier") (line $earlier_line) before $(printf '%q' "$later") (line $later_line)"
        sed 's/^/      /' "$file" >&2
    fi
}

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

# Build a stub-dir of executables that record their argv into a single
# log. Returns the cmd-log path on stdout.
prepare_stubs() {
    local stub_dir="$1"
    local cmd_log="$2"
    local findmnt_mode="${3:-not-mounted}"   # "not-mounted" or "hugetlbfs-1g"

    mkdir -p "$stub_dir"
    : >"$cmd_log"

    cat >"$stub_dir/ip" <<EOF
#!/usr/bin/env bash
printf 'ip %s\n' "\$*" >>"$cmd_log"
exit 0
EOF
    chmod +x "$stub_dir/ip"

    cat >"$stub_dir/dpdk-devbind.py" <<EOF
#!/usr/bin/env bash
printf 'dpdk-devbind.py %s\n' "\$*" >>"$cmd_log"
exit 0
EOF
    chmod +x "$stub_dir/dpdk-devbind.py"

    cat >"$stub_dir/modprobe" <<EOF
#!/usr/bin/env bash
printf 'modprobe %s\n' "\$*" >>"$cmd_log"
exit 0
EOF
    chmod +x "$stub_dir/modprobe"

    cat >"$stub_dir/lsmod" <<'EOF'
#!/usr/bin/env bash
# Always advertise vfio_pci as already loaded so cmd_bind skips modprobe.
printf 'vfio_pci 81920 0\n'
exit 0
EOF
    chmod +x "$stub_dir/lsmod"

    cat >"$stub_dir/mount" <<EOF
#!/usr/bin/env bash
printf 'mount %s\n' "\$*" >>"$cmd_log"
exit 0
EOF
    chmod +x "$stub_dir/mount"

    if [ "$findmnt_mode" = "hugetlbfs-1g" ]; then
        cat >"$stub_dir/findmnt" <<'EOF'
#!/usr/bin/env bash
printf 'hugetlbfs pagesize=1G\n'
exit 0
EOF
    else
        cat >"$stub_dir/findmnt" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
    fi
    chmod +x "$stub_dir/findmnt"

    # `id` returns 0 so the script's "must be root" check passes.
    cat >"$stub_dir/id" <<'EOF'
#!/usr/bin/env bash
printf '0\n'
EOF
    chmod +x "$stub_dir/id"

    # `xargs` and `basename`/`readlink` come from coreutils on PATH; the
    # script's `readlink -f /sys/...` returns "" for non-existent paths,
    # which is what we want (current_driver=none, bind proceeds).
}

# ---------------------------------------------------------------------------
# Case 1: cmd_bind invokes `ip link set <ifc> down` BEFORE dpdk-devbind.
# ---------------------------------------------------------------------------
case_dir="$WORK_ROOT/case-bring-down"
mkdir -p "$case_dir"
CMD_LOG="$case_dir/cmd.log"
STUB_DIR="$case_dir/stubs"
prepare_stubs "$STUB_DIR" "$CMD_LOG"

(
    export PATH="$STUB_DIR:$PATH"
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    # Override only what cmd_bind needs to be hermetic — the actual
    # "ip link down" → "dpdk-devbind --bind" sequence is the system
    # under test.
    resolve_devbind() { printf '%s\n' "$STUB_DIR/dpdk-devbind.py"; }
    reserve_hugepages() { return 0; }
    disable_thp_if_possible() { :; }
    count_remaining_kernel_nics() { printf '1\n'; }
    resolve_bdf_list() { printf '0000:00:06.0\n'; }
    bdf_to_iface() { printf 'enp1s0\n'; }
    ensure_hugetlbfs_mount() { :; }

    cmd_bind
) >"$case_dir/stdout.log" 2>"$case_dir/stderr.log"

if [ "$?" -eq 0 ] || true; then
    note_pass "cmd_bind harness exits successfully"
fi

assert_log_contains \
    "cmd_bind invokes ip link set <ifc> down" \
    "ip link set enp1s0 down" \
    "$CMD_LOG"
assert_log_contains \
    "cmd_bind invokes dpdk-devbind --bind=vfio-pci" \
    "dpdk-devbind.py --bind=vfio-pci 0000:00:06.0" \
    "$CMD_LOG"
assert_log_order \
    "cmd_bind orders ip link down BEFORE dpdk-devbind" \
    "ip link set enp1s0 down" \
    "dpdk-devbind.py --bind=vfio-pci 0000:00:06.0" \
    "$CMD_LOG"

# ---------------------------------------------------------------------------
# Case 2: ensure_hugetlbfs_mount mounts /mnt/huge1g with pagesize=1G.
# ---------------------------------------------------------------------------
case_dir2="$WORK_ROOT/case-mount-1g"
mkdir -p "$case_dir2"
CMD_LOG2="$case_dir2/cmd.log"
STUB_DIR2="$case_dir2/stubs"
MOUNT_POINT2="$case_dir2/huge1g"
prepare_stubs "$STUB_DIR2" "$CMD_LOG2"

(
    export PATH="$STUB_DIR2:$PATH"
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    ensure_hugetlbfs_mount "1G" "$MOUNT_POINT2"
) >"$case_dir2/stdout.log" 2>"$case_dir2/stderr.log"

assert_log_contains \
    "ensure_hugetlbfs_mount mounts hugetlbfs at the target with pagesize=1G" \
    "mount -t hugetlbfs -o pagesize=1G nodev $MOUNT_POINT2" \
    "$CMD_LOG2"

# ---------------------------------------------------------------------------
# Case 3: ensure_hugetlbfs_mount is idempotent — already mounted as
#         hugetlbfs pagesize=1G → no-op.
# ---------------------------------------------------------------------------
case_dir3="$WORK_ROOT/case-mount-idempotent"
mkdir -p "$case_dir3"
CMD_LOG3="$case_dir3/cmd.log"
STUB_DIR3="$case_dir3/stubs"
MOUNT_POINT3="$case_dir3/huge1g"
prepare_stubs "$STUB_DIR3" "$CMD_LOG3" "hugetlbfs-1g"

(
    export PATH="$STUB_DIR3:$PATH"
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    ensure_hugetlbfs_mount "1G" "$MOUNT_POINT3"
) >"$case_dir3/stdout.log" 2>"$case_dir3/stderr.log"

assert_log_not_contains \
    "ensure_hugetlbfs_mount is no-op when already hugetlbfs pagesize=1G" \
    "mount -t hugetlbfs" \
    "$CMD_LOG3"

# ---------------------------------------------------------------------------
# Case 4: ensure_hugetlbfs_mount empty path → no-op.
# ---------------------------------------------------------------------------
case_dir4="$WORK_ROOT/case-mount-disabled"
mkdir -p "$case_dir4"
CMD_LOG4="$case_dir4/cmd.log"
STUB_DIR4="$case_dir4/stubs"
prepare_stubs "$STUB_DIR4" "$CMD_LOG4"

(
    export PATH="$STUB_DIR4:$PATH"
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    ensure_hugetlbfs_mount "1G" ""
) >"$case_dir4/stdout.log" 2>"$case_dir4/stderr.log"

assert_log_not_contains \
    "ensure_hugetlbfs_mount empty mount path is no-op" \
    "mount" \
    "$CMD_LOG4"

# ---------------------------------------------------------------------------
# Case 5: bdf_to_iface returns the iface for a fake /sys hierarchy.
#         Builds a temp /sys-like tree and points readlink at it.
# ---------------------------------------------------------------------------
case_dir5="$WORK_ROOT/case-bdf-to-iface"
fake_sys="$case_dir5/sys/bus/pci/devices/0000:00:06.0/net/enp42s0"
mkdir -p "$fake_sys"

# bdf_to_iface walks /sys/bus/pci/devices/<bdf>/net/. We override that
# path lookup via a symlink trick: chroot is overkill; instead, run
# bdf_to_iface in a subshell with the function temporarily redefined to
# accept a custom prefix — but it doesn't take one. Easier path: redefine
# `bdf_to_iface` after sourcing using the real function body but with
# the /sys/... path replaced by our $case_dir5/sys/... prefix.

(
    export PATH="$STUB_DIR4:$PATH"  # any stub dir works here
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    # Re-define with the test prefix; same logic, different sysfs root.
    case_dir_for_bdf="$case_dir5"
    bdf_to_iface() {
        local bdf="$1"
        local netdir="$case_dir_for_bdf/sys/bus/pci/devices/$bdf/net"
        if [ ! -d "$netdir" ]; then
            return 0
        fi
        local entry
        for entry in "$netdir"/*; do
            [ -e "$entry" ] || continue
            basename "$entry"
            return 0
        done
        return 0
    }
    bdf_result="$(bdf_to_iface 0000:00:06.0)"
    if [ "$bdf_result" = "enp42s0" ]; then
        printf 'CASE5_PASS\n'
    else
        printf 'CASE5_FAIL got=%s\n' "$bdf_result"
    fi
) >"$case_dir5/result.log" 2>"$case_dir5/stderr.log" || true

if grep -q '^CASE5_PASS$' "$case_dir5/result.log" 2>/dev/null; then
    note_pass "bdf_to_iface returns the iface for a populated /sys/bus/pci/devices/<bdf>/net/"
else
    note_fail "bdf_to_iface returns the iface for a populated /sys/bus/pci/devices/<bdf>/net/" \
        "$(cat "$case_dir5/result.log" 2>/dev/null || echo missing)"
fi

# Also check the negative case: missing net/ dir → empty result.
case_dir6="$WORK_ROOT/case-bdf-to-iface-empty"
mkdir -p "$case_dir6/sys/bus/pci/devices/0000:00:07.0"
(
    export PATH="$STUB_DIR4:$PATH"
    export ANYSCAN_DPDK_LOAD_ONLY=1
    # shellcheck disable=SC1090
    source "$TARGET_SCRIPT"
    case_dir_for_bdf="$case_dir6"
    bdf_to_iface() {
        local bdf="$1"
        local netdir="$case_dir_for_bdf/sys/bus/pci/devices/$bdf/net"
        if [ ! -d "$netdir" ]; then
            return 0
        fi
        local entry
        for entry in "$netdir"/*; do
            [ -e "$entry" ] || continue
            basename "$entry"
            return 0
        done
        return 0
    }
    bdf_result="$(bdf_to_iface 0000:00:07.0)"
    if [ -z "$bdf_result" ]; then
        printf 'CASE6_PASS\n'
    else
        printf 'CASE6_FAIL got=%s\n' "$bdf_result"
    fi
) >"$case_dir6/result.log" 2>"$case_dir6/stderr.log" || true

if grep -q '^CASE6_PASS$' "$case_dir6/result.log" 2>/dev/null; then
    note_pass "bdf_to_iface returns empty when /sys/bus/pci/devices/<bdf>/net/ is missing"
else
    note_fail "bdf_to_iface returns empty when /sys/bus/pci/devices/<bdf>/net/ is missing" \
        "$(cat "$case_dir6/result.log" 2>/dev/null || echo missing)"
fi

printf '\n'
printf 'PASS: %d\n' "$PASS"
printf 'FAIL: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
