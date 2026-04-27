# AF_XDP Integration Plan for the AnyScan Port Scanner (v1)

> **Status:** Phase 1 design — design + dependency survey + LOC/effort estimate. **No scanner C code is changed by this PR.** Phase 2 implementation is gated on user/orchestrator approval after this plan merges.
>
> **Scope owner:** AnyScan port-scan I/O path. Adapter orchestration (`anyscan_rate_controller.py`) and prod runtime config are explicitly out of scope (owned by anygpt-33 and ops respectively).
>
> **Date:** 2026-04-27
> **Author session:** anygpt-34
> **Companion brief:** anygpt-32 scope memo PR #63 (scanner = `github.com/Lorikazzzz/VulnScanner-zmap-alternative-`, 3.3K LOC C, masscan+zmap hybrid).

---

## 1. Problem and goal

**Goal:** add an `AF_XDP` ("XSK") I/O path to the bundled C scanner so the per-NIC packet-rate ceiling moves from the kernel `AF_PACKET` TX path to the ENA hardware/backplane.

**Why now:**

- The `c6in.metal` multi-NIC bench in anygpt-4 hit **12.8 Mpps aggregate at 4 ENIs**. The bottleneck is the host kernel TX/syscall path: a single `AF_PACKET` `PACKET_TX_RING` (TPACKET_V2) socket caps near 3 Mpps even with `PACKET_QDISC_BYPASS`. The Python adapter already documents this — see `vulnscanner-zmap-adapter.py:669` ("A single AF_PACKET socket caps around 3M pps under the bundled scanner").
- ENA on c6in supports native AF_XDP zero-copy. The driver-level theoretical ceiling on c6in.metal is in the **100 Mpps** range across 4 ENIs combined; AF_XDP is the user-space path that lets user code actually approach that.
- `Lorikazzzz/VulnScanner-zmap-alternative-` already establishes an "alternate I/O path" pattern via the `USE_PFRING_ZC` build flag (`src/send-pfring.c`, `src/recv-pfring.c`). AF_XDP slots into the same shape with no architectural rework.

**Non-goals:**

- Replacing `AF_PACKET`. AF_PACKET stays the default and the unconditional fallback. AF_XDP is opt-in per worker.
- Touching the AIMD rate controller or adapter retry logic — anygpt-33 owns those.
- Bumping the AnyGPT submodule pointer in this PR. Phase 2 will produce a corresponding PR in `AnyVM-Tech/AnyGPT` once the AnyScan changes ship.
- Implementing C code in this PR. **Phase 1 is design only.**

---

## 2. What exists today (concrete walk-through)

This section grounds the design in the actual upstream source so reviewers don't have to re-discover it.

### 2.1 The two I/O paths today

| Path        | Files                                 | Build flag         | Status         |
|-------------|---------------------------------------|--------------------|----------------|
| AF_PACKET   | `src/sender.c`, `src/receiver.c`      | (default)          | Wired, in use  |
| PF_RING ZC  | `src/send-pfring.c`, `src/recv-pfring.c` | `USE_PFRING_ZC=1` | **Half-wired** (see §2.3) |

### 2.2 AF_PACKET sender (template for what AF_XDP must replace)

`src/sender.c:59-216` (`sender_thread`):

- Opens `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` (in `engine.c:161`, before the thread starts).
- Sets `PACKET_VERSION = TPACKET_V2`, `PACKET_TX_HAS_OFF`, `PACKET_QDISC_BYPASS`.
- Allocates a `PACKET_TX_RING` of `tp_block_size = 1 MiB × 64 blocks` with `tp_frame_size = 2048` (≈ 32K frames, 64 MiB per thread).
- Pre-fills every frame with a template SYN/UDP/ICMP packet built once.
- Per-batch (`BATCH_SIZE = 10`): pull next index from the BlackRock cipher (`blackrock_shuffle`), look up `(ip_idx, port_idx)`, splice the destination IP and port into the pre-filled frame, set `tp_status = TP_STATUS_SEND_REQUEST`, advance `frame_idx`, then `send(fd, NULL, 0, MSG_DONTWAIT)` to kick the kernel.
- Stats: `atomic_fetch_add(&ctx->stats->packets_sent, batch_count)`.
- Rate limiting: `rate_limit_batch(ctx, batch_count)` (`src/sender.c:32`).

The key invariants AF_XDP must preserve:

- **Same `thread_context_t` interface** (`include/scanner_defs.h:144`). Don't break `scan_method`, `current_global_idx`, BlackRock state, alive-queue interaction.
- **Same packet-construction helpers** (`create_syn_packet`, `create_udp_packet`, `create_icmp_packet`, `calculate_*_checksum`). All in `src/net.c` — re-use unchanged.
- **Same rate-limit hook** (`rate_limit_batch`). Already independent of socket type.

### 2.3 PF_RING ZC path is the right shape but **dispatch is not wired**

`src/send-pfring.c:4` defines `pfring_zc_sender_thread`. `include/scanner.h:10-11` declares it. **But `src/engine.c:165` unconditionally calls `pthread_create(&senders[i], NULL, sender_thread, &scan_ctx[i])`** — there is no `#ifdef USE_PFRING_ZC` selector and no function-pointer indirection. The ZC files compile when the flag is set but never get invoked.

This is a pre-existing wart in upstream. The AF_XDP plan **must fix dispatch as part of the same change** (§3.3) — otherwise we land a third dead I/O backend. The fix is small (~30 LOC in `engine.c`) and naturally belongs with the I/O-abstraction work, so it stays in scope rather than being spun out as a prereq PR.

### 2.4 How AnyScan invokes the scanner today

- `vulnscanner-zmap-adapter.py:118` resolves the `scanner` binary (PATH → `bin/scanner` → `/usr/bin/scanner`).
- `run_static_scanner` / `run_dynamic_scanner` / `run_multi_nic_scanner` (`vulnscanner-zmap-adapter.py:495,528,783`) build argv from a JSON invocation.
- `install-external-deps.sh:11-21` clones `Lorikazzzz/VulnScanner-zmap-alternative-` and runs plain `make`.
- `install-worker-bundle.sh:53` ships the resulting binary as `/opt/agentd/bin/scanner`.

Nothing in this chain currently passes a build flag through `make`. Phase 2 will add `make USE_AF_XDP=1` in `install-external-deps.sh` and a runtime opt-in in the adapter (§3.6).

---

## 3. Proposed architecture

### 3.1 File layout

Two new C files in the upstream scanner repo, mirroring the PF_RING template:

| File                                | Purpose                                                                                         | Est. LOC |
|-------------------------------------|-------------------------------------------------------------------------------------------------|----------|
| `src/send-afxdp.c`                  | `xdp_sender_thread`: XSK setup, UMEM alloc, TX ring batching, completion-ring drain, kick path. | ~280     |
| `src/recv-afxdp.c`                  | `xdp_receiver_thread`: XSK RX ring poll, fill-ring refill, packet hand-off to existing `process_packet`. | ~120 |
| `include/xdp-defs.h`                | Shared XSK structs (`xsk_state_t`, `umem_state_t`), AF_XDP-only includes, sizing constants. | ~60      |
| `src/engine.c` (modify)             | Function-pointer dispatch table for `{sender,receiver}_thread`; per-thread XSK init helper.     | ~50 (delta) |
| `include/scanner_defs.h` (modify)   | Add XSK fields to `thread_context_t` under `#ifdef USE_AF_XDP`; add CLI/config fields.          | ~25 (delta) |
| `include/scanner.h` (modify)        | Declare `xdp_sender_thread`, `xdp_receiver_thread` under `#ifdef USE_AF_XDP`.                   | ~5 (delta)  |
| `src/conf.c` (modify)               | New `--io-engine={af_packet,af_xdp}` CLI flag, plumbing to `scanner_config_t`.                   | ~30 (delta) |
| `Makefile` (modify)                 | `USE_AF_XDP=1` conditional that adds `-DUSE_AF_XDP`, `-lxdp -lbpf -lelf`, and the new sources.  | ~10 (delta) |

**Estimated total: ~580 LOC (450 net new + ~130 in modified files).** This is in the same ballpark as the brief's 450-500 estimate; the extra ~80 covers (a) the dispatch-refactor that's required to wire the existing PF_RING path correctly and (b) a slightly larger send-afxdp.c than the trivial 103-LOC `send-pfring.c` because XSK setup is more verbose than handing off to a pre-baked PF_RING ZC pool.

### 3.2 Where things slot in (architecture diagram)

```
                ┌─────────────────────────────────────────────────────────┐
                │  main.c → conf.c (parse_arguments)                       │
                │             ▼                                            │
                │  config.io_engine ∈ { AF_PACKET, AF_XDP }                │
                │             ▼                                            │
                │  engine.c::setup_scan → engine.c::run_scan               │
                │             ▼                                            │
                │   io_engine_vtable_t v = pick_io_engine(config);         │  ◄── new in §3.3
                │             ▼                                            │
                │   for i in senders:                                      │
                │     v.init_socket(&scan_ctx[i], config)  ────┐           │
                │     pthread_create(senders[i], v.tx_thread)  │           │
                │             ▼                                ▼           │
                │   ┌────────────────────────┐  ┌──────────────────────┐   │
                │   │ AF_PACKET (default)    │  │ AF_XDP (USE_AF_XDP)  │   │
                │   │ sender.c::sender_thread│  │ send-afxdp.c::       │   │
                │   │   socket(PF_PACKET,…)  │  │   xdp_sender_thread  │   │
                │   │   PACKET_TX_RING       │  │     XSK + UMEM       │   │
                │   │   sendto(MSG_DONTWAIT) │  │     xsk_ring_prod__* │   │
                │   └────────────────────────┘  └──────────────────────┘   │
                │             ▼                              ▼             │
                │   shared: net.c (packet build), blackrock, rate limit    │
                └─────────────────────────────────────────────────────────┘
```

The two paths share **everything above the I/O socket boundary**: packet construction, BlackRock shuffle, rate limiting, blacklist filter, alive-queue, stats. AF_XDP is purely a TX/RX descriptor swap.

### 3.3 Dispatch refactor (resolves §2.3 PF_RING wart)

Introduce a small `io_engine_vtable_t` in `include/scanner_defs.h`:

```c
typedef struct {
    int  (*init_per_thread)(thread_context_t *ctx);      /* socket + ring setup */
    void *(*tx_thread)(void *arg);                        /* sender entry */
    void *(*rx_thread)(void *arg);                        /* receiver entry */
    void  (*teardown_per_thread)(thread_context_t *ctx);
    const char *name;
} io_engine_vtable_t;

extern const io_engine_vtable_t io_engine_af_packet;
#ifdef USE_AF_XDP
extern const io_engine_vtable_t io_engine_af_xdp;
#endif
#ifdef USE_PFRING_ZC
extern const io_engine_vtable_t io_engine_pfring_zc;
#endif
```

`engine.c::run_scan` then resolves `config->io_engine` to one of the registered vtables (`pick_io_engine`), calls `v.init_per_thread(&scan_ctx[i])` instead of the inline `socket(PF_PACKET, …)` it does today (`engine.c:161-164`), and `pthread_create(…, v.tx_thread, …)` instead of the hardcoded `sender_thread`. This pattern is small, doesn't disturb the AF_PACKET behaviour at runtime, and gives PF_RING ZC its missing dispatch for free.

### 3.4 Per-NIC AF_XDP setup

#### Socket model

- **One XSK socket per `(NIC, queue_id)` pair**, owned by exactly one sender thread. This matches Suricata's per-RSS-queue worker model (see [Suricata 8.0 AF_XDP docs](https://docs.suricata.io/en/suricata-8.0.0/capture-hardware/af-xdp.html)) and is the right granularity for ENA's multi-channel layout.
- **TX-only socket**: pass `rx = NULL` to `xsk_socket__create` ([eBPF docs](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_socket__create)). The Linux kernel docs explicitly recommend not putting packets on the fill ring for TX-only sockets (see [docs.kernel.org/networking/af_xdp.html](https://docs.kernel.org/networking/af_xdp.html)). The receiver path uses a separate XSK with `tx = NULL`.
- **No custom XDP program**: with `rx = NULL`, libxdp does not load the default `xsks_map` redirect program. For the RX side we use libxdp's default redirect program (`xsk_setup_xdp_prog` per [eBPF docs](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_setup_xdp_prog)). No clang/llvm at runtime; only at build time if we ever ship a custom program — Phase 1 plan does not.

#### UMEM and ring sizing

Per-XSK:

| Region            | Size                  | Rationale                                                                            |
|-------------------|-----------------------|--------------------------------------------------------------------------------------|
| Frame size        | 2048 B                | `XSK_UMEM__DEFAULT_FRAME_SIZE`. SYN/UDP probes are <100 B; jumbo not needed.         |
| UMEM frame count  | 8192                  | 16 MiB per worker (matches Suricata default). Holds 4× the TX ring.                  |
| TX ring           | 2048 desc             | `XSK_RING_PROD__DEFAULT_NUM_DESCS`. ~10 Mpps drains it in 200 µs at line rate.       |
| Completion ring   | 2048 desc             | Symmetry with TX.                                                                    |
| Fill ring (RX XSK only) | 2048 desc       | Refilled in receiver thread loop.                                                    |
| RX ring (RX XSK only)   | 2048 desc       | —                                                                                    |
| `bind_flags`      | `XDP_USE_NEED_WAKEUP` | Standard kernel-side config; `xsk_ring_prod__needs_wakeup` decides when to `sendto`. |
| `xdp_flags`       | `XDP_FLAGS_DRV_MODE` `\| XDP_ZEROCOPY` | Native zero-copy on ENA (driver supports it; see §3.5). Falls back to `XDP_FLAGS_SKB_MODE` (generic) if ENA refuses ZC for this queue. |

NUMA awareness: c6in.metal has multi-NUMA. UMEM is allocated with `posix_memalign(PAGE_SIZE, …)` on the thread's NUMA node (use `numa_alloc_onnode` if `libnuma` is linked; fall back to plain `posix_memalign` if not, since dual-NUMA c6in.metal still works correctly with default page placement, just slightly slower). Defer the libnuma decision to Phase 2 — measure first.

#### Memory budget on c6in.metal (4 ENIs)

- 4 ENIs × N TX queues × 16 MiB UMEM = **256 MiB if 4 queues/NIC**, **64 MiB at 1 queue/NIC**.
- c6in.metal has 192 GiB RAM. Even at 16 queues/NIC × 4 NICs we're at 1 GiB total — negligible.

#### TX loop pattern (the `xdp_sender_thread` body, sketch)

Reference: [xdp-project/bpf-examples/AF_XDP-example/xdpsock.c](https://github.com/xdp-project/bpf-examples/blob/main/AF_XDP-example/xdpsock.c) `tx_only` and `complete_tx_only` functions.

1. Outer loop while `ctx->running && !stop_signal && more_work`.
2. Inner: `n = xsk_ring_prod__reserve(&tx, BATCH_SIZE, &idx)`. If `n == 0`, drain completions then `continue`.
3. For each reserved slot: pick next BlackRock index (same as `sender.c:144`), build packet **into the UMEM frame** at `umem_offset = (frame_id * FRAME_SIZE)`, set `desc->addr = umem_offset; desc->len = pkt_len`.
4. `xsk_ring_prod__submit(&tx, n)`.
5. If `xsk_ring_prod__needs_wakeup(&tx)`: `sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`.
6. Drain completion ring: `c = xsk_ring_cons__peek(&comp, BATCH_SIZE, &cidx); xsk_ring_cons__release(&comp, c);` and recycle frames.
7. `atomic_fetch_add(&stats->packets_sent, n); rate_limit_batch(ctx, n);`.

The frame-recycle bookkeeping is the only significant new code vs. the AF_PACKET path; AF_PACKET's TPACKET_V2 ring auto-recycles via `tp_status`, AF_XDP requires us to track which UMEM frames the kernel has returned via the completion ring.

### 3.5 ENA / AWS specifics

- **Driver support**: ENA gained XDP in driver v2.2.0; native AF_XDP zero-copy is supported per [amzn-drivers README](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/README.rst) ("The driver supports native AF XDP (zero copy)").
- **Lower-half-channels constraint**: ENA only allows zero-copy XSK on **channels 0..N/2-1**. On c6in.metal (≥64 channels) this is non-binding, but the implementation must (a) query `ethtool -l` channel count, (b) cap the per-NIC XSK count at half, (c) fall back to `XDP_FLAGS_SKB_MODE` (copy mode) if the bind fails.
- **Known issues to encode as test cases**:
  - [amzn-drivers#221](https://github.com/amzn/amzn-drivers/issues/221) — historical "XDP zero-copy makes driver reset" regression. Phase 2 must verify on the actual AMI we ship before enabling ZC by default.
  - [amzn-drivers commit b952df8](https://github.com/amzn/amzn-drivers/commit/b952df81751938a1912958ae92a465ab96e11548) — c6gn-specific XDP_REDIRECT fix; c6in is on a different NIC family but the bug class (silent drops on redirect) should be on the test plan.
  - LPC (Local Page Cache) is disabled when XDP is active OR when fewer than 16 queue pairs exist. Don't be surprised by changed RX-side perf characteristics during AF_XDP receive testing.
- **Generic mode fallback**: if `XDP_FLAGS_DRV_MODE` bind fails (e.g. older kernel, ENA driver too old), the code falls back to `XDP_FLAGS_SKB_MODE`. In generic mode the kernel still copies into skbs — perf gain over AF_PACKET shrinks but does not disappear (still bypasses the qdisc and most of the netdev path).

### 3.6 Build-system integration

Append to `Makefile` (currently 29 lines):

```make
ifeq ($(USE_AF_XDP),1)
    CFLAGS += -DUSE_AF_XDP
    LDFLAGS += -lxdp -lbpf -lelf -lz
    SRCS += src/send-afxdp.c src/recv-afxdp.c
endif
```

Mirrors the existing `USE_PFRING_ZC` block (Makefile lines 10-14). The two flags are mutually compatible at compile time but mutually exclusive at runtime (selected by `--io-engine=`).

`install-external-deps.sh` (line 67, the `make` invocation) gains `USE_AF_XDP="${ANYSCAN_USE_AF_XDP:-0}"` env-driven plumbing; default off so existing AMIs continue to build the same binary.

### 3.7 CLI / config plumbing

In `src/conf.c` (currently 157 lines), add to `parse_arguments`:

- New long option `--io-engine=NAME` (case 1005 or similar).
- Accept `af_packet` (default), `af_xdp`, `pfring_zc`.
- Reject unknown values with a clear error.
- New `--xdp-zerocopy=auto|force|off` (default `auto`) — Phase 2 may also want `--xdp-num-queues=N`. Defer the latter to Phase 2 once we have a benchmark on c6in.metal that tells us the right shape.

Add to `scanner_config_t` (`include/scanner_defs.h:85`):

```c
enum io_engine { IO_ENGINE_AF_PACKET = 0, IO_ENGINE_AF_XDP, IO_ENGINE_PFRING_ZC };
int io_engine;
int xdp_zerocopy;       /* 0=off, 1=force, 2=auto */
int xdp_num_queues;     /* 0 = auto-detect via ethtool */
```

The Python adapter (`vulnscanner-zmap-adapter.py`) will need a new optional `io_engine` field in its invocation JSON. Phase 2 work; Phase 1 just notes it.

---

## 4. Dependency surface

### 4.1 Build-time

| Package        | Min version | Purpose                         | Notes                                                                                          |
|----------------|-------------|---------------------------------|------------------------------------------------------------------------------------------------|
| `libxdp-dev`   | 1.2         | `<xdp/xsk.h>` public AF_XDP API | Ubuntu 24.04 ships 1.4.2 ([Launchpad](https://launchpad.net/ubuntu/noble/amd64/libxdp-dev)). Ubuntu 22.04 does **not** ship it in main — needs PPA/source build. Debian bookworm ships 1.3.0. |
| `libbpf-dev`   | 0.7         | XSK helpers, transitive dep     | Ubuntu 22.04 ships 0.5 (too old for stable XSK API). 24.04 fine.                              |
| `libelf-dev`   | any         | libbpf transitive               | —                                                                                              |
| `zlib1g-dev`   | any         | libbpf transitive               | —                                                                                              |
| `linux-headers`| host kernel | only if shipping a custom XDP program | **Phase 1 plan does not**. Skip.                                                          |
| `clang`, `llvm`| any         | only if compiling a custom XDP program | Same — skip.                                                                          |

**Recommended baseline AMI: Ubuntu 24.04 (`Noble`)** because libxdp-dev is in main. If we must support Ubuntu 22.04 we'll need to either (a) add the `xdp-tools` PPA in `install-external-deps.sh`, or (b) vendor libxdp as a submodule and build it from source. Decision deferred to Phase 2 once we know what the AnyScan worker AMI baseline actually is.

### 4.2 Runtime (already-deployed bundle install)

Add to `install-worker-bundle.sh` (or the upstream `install-external-deps.sh` apt block, whichever ships earliest in the worker bootstrap chain):

```bash
apt-get install -y --no-install-recommends \
    libxdp1 libbpf1 libelf1 libz1
```

(Names are runtime `.so` packages, not `-dev`. On older Ubuntu they may be `libxdp0` / `libbpf0` — `install-external-deps.sh` already uses `apt` patterns elsewhere; reuse them.)

### 4.3 Kernel feature checks

Phase 2 must add a runtime probe on scanner startup (when `--io-engine=af_xdp`):

1. `uname -r` ≥ 5.10. Earlier kernels have AF_XDP but `XDP_USE_NEED_WAKEUP` quirks.
2. `/sys/class/net/<iface>/device/driver` is `ena` (sanity log; not a hard gate).
3. `ethtool -l <iface>` returns ≥1 channel — required for queue binding.
4. Try `XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY` first; on `EOPNOTSUPP` retry without `XDP_ZEROCOPY`; on still-failing retry with `XDP_FLAGS_SKB_MODE`. Log which mode actually bound.

### 4.4 Capabilities

AF_XDP requires `CAP_NET_RAW` and `CAP_BPF` (kernel ≥ 5.8) or `CAP_SYS_ADMIN` (older). The scanner already runs with `CAP_NET_RAW` (raw sockets). The systemd unit (`anyscan-worker.service`) must add `AmbientCapabilities=CAP_NET_RAW CAP_BPF` (and `CapabilityBoundingSet=` matching). Phase 2 task; out of scope to edit prod systemd in Phase 1.

---

## 5. Test plan

### 5.1 Synthetic loopback bench (Phase 2 task 1)

- Two veth pairs in a netns. Scanner sends with `--io-engine=af_xdp` to one veth; receiver counts via `xdpdump` or a tiny libpcap counter on the peer.
- Pass criteria: scanner-reported `packets_sent` rate ≥ 90% of theoretical for veth (~5 Mpps in `XDP_FLAGS_SKB_MODE`; veth doesn't have `DRV_MODE`).
- Regression criteria: with `--io-engine=af_packet` (default), behavior and reported pps within ±2% of `main` baseline.

### 5.2 Unit-style verification (no live NICs)

- A small `tests/` harness (~150 LOC, **does not exist upstream — would be net-new**) that:
  - Allocates a UMEM in a netns.
  - Spawns one `xdp_sender_thread` against a veth.
  - Verifies frames land at the peer with correct dst-IP rotation per BlackRock cipher (regression test for the index→packet plumbing).
- Decision: do we ship this test harness with the upstream repo or keep it in AnyScan? Vote: keep it in AnyScan as a `tests/integration/` script that builds and runs the scanner in a netns. Avoids adding a test framework dependency to the upstream C scanner.

### 5.3 Live `c6in.metal` bench (Phase 2 task 2)

- Single ENI: rate ramp 1M→25M pps in `--io-engine=af_xdp`. Pass: sustains ≥10 Mpps for 60s without driver reset (issue #221 watch).
- 4 ENI: rerun the anygpt-4 bench shape. Target: aggregate ≥40 Mpps (3.1× the 12.8M AF_PACKET ceiling). Stretch: 80 Mpps.
- Capture: `ethtool -S <iface>` deltas (`tx_packets`, `bw_in_allowance_exceeded`), `bpftool net show`, host CPU per-core, observed scan completion time vs AF_PACKET baseline.

### 5.4 Fallback regression

- `--io-engine=af_packet` (the default) must remain bit-for-bit identical to `main`. Phase 2 PR includes a CI job that runs the existing AF_PACKET smoke test unchanged.
- `--io-engine=af_xdp` on a non-ENA NIC (e.g., a CI VM with `virtio_net`) must either work in `XDP_FLAGS_SKB_MODE` or fail loudly with a one-line error pointing at `--io-engine=af_packet`.

### 5.5 Adapter-level integration (Phase 2 task 3)

- AnyScan adapter (`vulnscanner-zmap-adapter.py`) gains optional `io_engine` field. Default unset → AF_PACKET (zero behavior change).
- Multi-NIC orchestrator (`run_multi_nic_scanner` at `vulnscanner-zmap-adapter.py:783`) propagates `io_engine` per child invocation.
- Verify: the existing AIMD controller (`anyscan_rate_controller.py`, owned by anygpt-33 — **read-only for this work**) doesn't choke on the higher achievable rates. May need a one-line ceiling bump in a follow-up coordinated with anygpt-33.

---

## 6. Risk register

| Risk                                                | Likelihood | Impact      | Mitigation                                                                                                     |
|-----------------------------------------------------|------------|-------------|----------------------------------------------------------------------------------------------------------------|
| ENA AF_XDP driver-reset (amzn-drivers#221)          | Medium     | High        | Test on actual prod AMI before flipping default; keep `--io-engine=af_packet` as one-flag rollback.            |
| libxdp version skew across worker AMIs              | Medium     | Medium      | Pin to Ubuntu 24.04 baseline; document the 22.04 fallback path (PPA or vendor); runtime probe logs version.    |
| Per-queue ZC limited to lower-half channels         | Low (on c6in.metal) | Medium | Probe `ethtool -l`, bind only to allowed channels; SKB-mode fallback per-queue.                                |
| Custom XDP program drift from upstream libxdp default | Low (we don't ship one in v1) | Low | Phase 1 explicitly avoids shipping a custom XDP/eBPF program.                                                  |
| LPC perf surprise on RX after enabling XDP          | Medium     | Low         | Documented in §3.5; receiver path is not the bottleneck so a small RX regression is acceptable.                |
| AIMD controller cannot keep up with new pps ceiling | High       | Medium      | Coordinate with anygpt-33 before flipping AF_XDP on by default; the AIMD ceiling parameter likely needs a bump. |
| Kernel < 5.10 on some legacy worker hosts           | Low        | High (if hit) | Runtime probe gates AF_XDP off and logs; falls back to AF_PACKET cleanly.                                      |
| systemd unit missing `CAP_BPF`                      | High (will hit on first prod run) | High | Phase 2 PR includes systemd unit edit; Phase 1 just records the dependency.                                    |
| Phase 2 LOC estimate slips                          | Medium     | Low         | Subdivide Phase 2 into the four PRs in §8 so a slip in one doesn't block the others.                           |

---

## 7. Effort estimate

Honest engineering time, assuming one experienced C / Linux-networking engineer with AF_XDP familiarity, working from this plan:

| Phase 2 chunk                                          | Effort     | Verification gate                                     |
|--------------------------------------------------------|------------|-------------------------------------------------------|
| 2a. Dispatch refactor + vtable (no AF_XDP yet)         | 1 day      | `make` + AF_PACKET smoke test unchanged.              |
| 2b. `send-afxdp.c` + `recv-afxdp.c` + headers          | 2-3 days   | Compiles with `USE_AF_XDP=1`; veth loopback test.     |
| 2c. CLI plumbing + runtime probe + ENA-channel logic   | 1 day      | `--io-engine=af_xdp` works on a CI VM in SKB mode.    |
| 2d. `install-external-deps.sh` + systemd-unit caps     | 0.5 day    | Worker bootstrap on a fresh Ubuntu 24.04 AMI.         |
| 2e. Live c6in.metal bench + regression sweep            | 1-2 days   | §5.3 pass criteria.                                   |
| 2f. AnyScan adapter `io_engine` propagation            | 0.5 day    | Existing AnyScan tests + manual multi-NIC invocation. |
| **Total**                                              | **6-8 days** | —                                                   |

This is the *implementation* envelope. Add 2-3 days for review, CI-flake hunting, and a brief production canary before flipping `io_engine: af_xdp` on by default.

---

## 8. Rollout plan

1. **Plan PR (this PR)** lands in `AnyVM-Tech/AnyScan` `perf/portscan-afxdp-plan` → `main`. Reference doc only.
2. **Phase 2a-d PRs** ship to upstream `Lorikazzzz/VulnScanner-zmap-alternative-` (or its AnyVM-Tech fork — see §9 open question 1) as four small PRs in order. Each is independently buildable and AF_PACKET-compatible by default.
3. **Phase 2e bench** runs on a fresh c6in.metal worker. Numbers go in a follow-up bench memo PR.
4. **AnyScan adapter PR** propagates the `io_engine` field but **defaults to `af_packet`**. Worker bundle ships with AF_XDP code-paths present but disabled.
5. **Manual canary**: enable `--io-engine=af_xdp` on a single c6in.metal worker via `runtime.env`. Run for 48 h, watch `dmesg`, watch ENA stats, watch hit-rate. (Note: editing prod `runtime.env` is owned by ops; out of scope for these worker tasks.)
6. **Gradual default-on**: after 48 h clean, flip the AnyScan worker bundle default to `af_xdp` for c6in.metal tier specifically. Keep AF_PACKET default for other tiers until equivalent benches are run.
7. **AnyGPT submodule bump**: standard `chore: bump apps/anyscan submodule pointer` PR after each AnyScan release lands.

Rollback at any step: a one-line config flip back to `--io-engine=af_packet`. The code path is opt-in by design, so revert is a config change, not a code revert.

---

## 9. Open questions (do not block this plan PR)

1. **Where do the C changes live?** Upstream `Lorikazzzz/VulnScanner-zmap-alternative-` is third-party. Options: (a) PR upstream, (b) maintain a fork under `AnyVM-Tech/`, (c) carry a patch in `install-external-deps.sh`. Recommendation: (b) fork at `AnyVM-Tech/anyscan-engine-c` and update `install-external-deps.sh:11` to point there. Decide before Phase 2 starts.
2. **libnuma optional dep**: c6in.metal is dual-NUMA. Is a 5-10% perf gain from NUMA-aware UMEM allocation worth the optional dep? Defer to a Phase 2 micro-bench.
3. **`SO_PREFER_BUSY_POLL`** (kernel ≥ 5.11) for the RX side — relevant only if we extend AF_XDP to the receiver path simultaneously. Phase 1 plan ships the receiver path; if Phase 2 wants to start TX-only, that's a smaller scope.
4. **AIMD ceiling coordination with anygpt-33**: confirm the controller has a configurable max-rate parameter; if not, flag it for that worker's roadmap.

---

## 10. References

**libxdp / AF_XDP API**:
- [docs.kernel.org/networking/af_xdp.html](https://docs.kernel.org/networking/af_xdp.html) — kernel-side reference.
- [docs.ebpf.io libxdp functions](https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_socket__create) — `xsk_socket__create`, `xsk_umem__create`, `xsk_ring_prod__reserve`, `xsk_ring_prod__submit`, `xsk_ring_prod__needs_wakeup`, `xsk_ring_prod__tx_desc`, `xsk_setup_xdp_prog`.
- [xdp-project/xdp-tools `xsk.h`](https://github.com/xdp-project/xdp-tools/blob/main/headers/xdp/xsk.h).

**Reference implementations**:
- [xdp-project/bpf-examples AF_XDP-example/xdpsock.c](https://github.com/xdp-project/bpf-examples/blob/main/AF_XDP-example/xdpsock.c) — canonical kernel sample (relocated out of tree).
- [xdp-project/xdp-tutorial advanced03-AF_XDP](https://github.com/xdp-project/xdp-tutorial/blob/main/advanced03-AF_XDP/af_xdp_user.c) — teaching reference.
- [Suricata 8.0 AF_XDP capture](https://docs.suricata.io/en/suricata-8.0.0/capture-hardware/af-xdp.html) — production per-queue worker model, sizing defaults.
- [dnsdist XSK doc](https://www.dnsdist.org/advanced/xsk.html) — small, readable userspace integration.
- [gregdel/tg](https://github.com/gregdel/tg) — minimal AF_XDP-TX traffic-generator template.

**ENA / AWS specifics**:
- [amzn-drivers ENA README](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/README.rst) — AF_XDP support, lower-half-channels constraint, LPC interaction.
- [amzn-drivers RELEASENOTES](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/RELEASENOTES.md) — XDP/AF_XDP version history.
- [amzn-drivers#221](https://github.com/amzn/amzn-drivers/issues/221) — ZC driver-reset regression to test for.
- [amzn-drivers#173](https://github.com/amzn/amzn-drivers/issues/173) — AF_XDP zero-copy enablement history.
- [Cloudflare AF_XDP corrupt-packets postmortem](https://blog.cloudflare.com/a-debugging-story-corrupt-packets-in-af_xdp-kernel-bug-or-user-error/) — production gotchas worth pre-empting.
- [Cloudflare AF_XDP / netns / cookie](https://blog.cloudflare.com/a-story-about-af-xdp-network-namespaces-and-a-cookie/) — netns interaction edges.

**Upstream scanner state survey**:
- No AF_XDP PR/issue in [zmap/zmap](https://github.com/zmap/zmap) or [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) as of 2026-04. masscan tracks PF_RING ZC ([#358](https://github.com/robertdavidgraham/masscan/issues/358)). This plan is net-new, not a port of an abandoned branch.

**AnyScan / AnyGPT internal**:
- anygpt-32 scope memo PR #63 — scanner identity confirmation.
- anygpt-4 bench notes — c6in.metal 4-NIC 12.8 Mpps result and bottleneck attribution.
- `vulnscanner-zmap-adapter.py:669` — adapter's existing comment that single AF_PACKET socket caps at 3 Mpps.
- `Makefile:10-14` (upstream scanner) — `USE_PFRING_ZC` build-flag template.
- `src/sender.c:59-216`, `src/send-pfring.c:1-103` (upstream scanner) — TPACKET_V2 vs PF_RING ZC patterns the new path mirrors.
- `src/engine.c:165` (upstream scanner) — pre-existing missing dispatch wart that this plan also resolves.
