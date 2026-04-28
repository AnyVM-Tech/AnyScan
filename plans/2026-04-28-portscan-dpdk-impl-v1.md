# DPDK Integration Plan for the AnyScan Port Scanner (v1)

> **Status:** Phase 1 design — design + dependency survey + LOC/effort estimate. **No engine C code is changed by this PR.** Phase 2 implementation is gated on user/orchestrator approval after this plan merges.
>
> **Scope owner:** AnyScan port-scan I/O path. Adapter orchestration (`anyscan_rate_controller.py`) and prod runtime config are explicitly out of scope (owned by anygpt-33 and ops respectively).
>
> **Date:** 2026-04-28
> **Author session:** anygpt-47
> **Companion briefs:**
> - PR #63 (`plans/2026-04-27-portscan-dpdk-scope-memo-v1.md`) — original DPDK scope memo, recommended deferral pending AF_XDP bench results.
> - PR #65 (`plans/2026-04-27-portscan-afxdp-plan-v1.md`) — AF_XDP integration plan; this plan mirrors its section structure.
> - PR #71 (`fix/afxdp-build-wireup`) — `ANYSCAN_USE_AF_XDP` build-flag wire-up template that the DPDK build flag will mirror.

---

## 1. Problem and goal

**Goal:** add a `DPDK` userspace-networking I/O path to the bundled C scanner so the per-NIC packet-rate ceiling moves from the kernel ENA driver path (where AF_XDP tops out at ~22 M pps aggregate on c6in.metal in `drv+copy` mode — see "why now") to the actual ENA hardware/backplane ceiling (50–100 M pps realistic on c6in.metal across all 8 ENIs).

**Why now:**

- The PR #65 plan landed AF_XDP. PR #71 wired the build flag through the bundle pipeline. **PR #65's c6in.metal bench then revealed a hard ENA-driver ceiling that is below the AF_XDP plan's projection**: AWS ENA on kernel ≤6.12.74 forces `drv+copy` (not `drv+zerocopy`) because of ENA's own constraint, capping the eight-NIC c6in.metal at ~22 M pps aggregate — 2.66× the 8.3 M pps AF_PACKET baseline, but only ~22–44% of the AF_XDP plan's 30–50 M pps projection. Memory of the bench result: `anyscan_afxdp_ena_constraint`.
- DPDK uses `vfio-pci` to bypass the kernel driver entirely. The ENA PMD (`net_ena` in mainline DPDK) does not have the kernel ENA driver's lower-half-channels-only ZC constraint, does not need `XDP_ZEROCOPY` cooperation from the kernel driver, and runs the TX ring entirely in userspace with no syscall overhead at all (vs AF_XDP's `sendto(MSG_DONTWAIT)` wakeup kicks).
- PR #63 deferred DPDK on the basis that AF_XDP "is also kernel-bypass-class and is supported natively by the in-tree ENA driver — likely sufficient for the throughput target without owning a scanner fork". That premise is invalidated by the PR #65 bench. Re-opening the question is the explicit point of PR #63's option 2 ("Fork the scanner under AnyVM-Tech and add DPDK there"). We have already done the fork half — `AnyVM-Tech/anyscan-engine-c` exists (PR #65 / #71 work landed there). The remaining work is the C code + build wire-up + host setup script.
- The AnyScan engine repo (`AnyVM-Tech/anyscan-engine-c`) **already has a working `io_engine_vtable_t` dispatch** (`src/engine.c:155-178`) with three slots wired (`af_packet`, `pfring_zc`, `af_xdp`) and a CLI flag (`--io-engine=`) plumbed in `src/conf.c:30-45,167-188`. DPDK slots into the same shape with no architectural rework — this is the single biggest reason DPDK is a different proposition today than it was in PR #63.

**Non-goals:**

- Replacing AF_PACKET or AF_XDP. Both stay. AF_PACKET is the unconditional fallback. AF_XDP stays as the "kernel-bypass without owning vfio-pci/hugepages" middle tier.
- Touching the AIMD rate controller (`anyscan_rate_controller.py`) — anygpt-33 owns it.
- Touching prod systemd units or `/etc/agentd/runtime.env` — ops owns it. (Phase 2 will produce a documented `runtime.worker.env.template` change but not edit the live env file.)
- Bumping the AnyGPT submodule pointer in this PR. Phase 2 will produce a corresponding `chore: bump apps/anyscan submodule pointer` PR after each AnyScan release lands.
- Implementing C code in this PR. **Phase 1 is design only.**
- Shipping a custom DPDK PMD or modifying `rte_net_ena`. We use the in-tree PMD as-is.

---

## 2. What exists today (concrete walk-through)

### 2.1 The three I/O paths today

| Path        | Files (in `AnyVM-Tech/anyscan-engine-c`) | Build flag         | Status                                       |
|-------------|------------------------------------------|--------------------|----------------------------------------------|
| AF_PACKET   | `src/sender.c`, `src/receiver.c`         | (default)          | Wired, in use                                |
| PF_RING ZC  | `src/send-pfring.c`, `src/recv-pfring.c` | `USE_PFRING_ZC=1`  | Dispatch wired (PR #65); cluster init still owned by a follow-on patch (commercial license) |
| AF_XDP      | `src/send-afxdp.c`, `src/recv-afxdp.c`, `include/xdp-defs.h` | `USE_AF_XDP=1`     | Wired and benched. Capped at ~22 M pps on c6in.metal due to the ENA ZC constraint. |

DPDK becomes the fourth. The vtable in `src/engine.c` already has the right shape for slotting in (§3.3).

### 2.2 The dispatch surface (template for what DPDK plugs into)

`include/scanner.h:42-64`:

```c
typedef struct {
    const char *name;
    int   (*init_per_thread)(thread_context_t *ctx, scanner_config_t *config);
    void *(*tx_thread)(void *arg);
    void *(*rx_thread)(void *arg);
    void  (*teardown_per_thread)(thread_context_t *ctx);
} io_engine_vtable_t;

extern const io_engine_vtable_t io_engine_af_packet;
#ifdef USE_PFRING_ZC
extern const io_engine_vtable_t io_engine_pfring_zc;
#endif
#ifdef USE_AF_XDP
extern const io_engine_vtable_t io_engine_af_xdp;
#endif

const io_engine_vtable_t *pick_io_engine(int io_engine);
const char *io_engine_name(int io_engine);
int io_engine_from_string(const char *name, int *out);
```

`src/engine.c:155-178` (`pick_io_engine`):

```c
const io_engine_vtable_t *pick_io_engine(int io_engine) {
    switch (io_engine) {
        case IO_ENGINE_AF_PACKET: return &io_engine_af_packet;
        case IO_ENGINE_PFRING_ZC:
#ifdef USE_PFRING_ZC
            return &io_engine_pfring_zc;
#else
            fprintf(stderr, "[-] --io-engine=pfring_zc requested but binary was not built with USE_PFRING_ZC=1\n");
            return NULL;
#endif
        case IO_ENGINE_AF_XDP:
#ifdef USE_AF_XDP
            return &io_engine_af_xdp;
#else
            fprintf(stderr, "[-] --io-engine=af_xdp requested but binary was not built with USE_AF_XDP=1\n");
            ...
            return NULL;
#endif
        default:
            fprintf(stderr, "[-] Unknown io_engine value: %d\n", io_engine);
            return NULL;
    }
}
```

`src/engine.c:308-321` (`run_scan` per-thread setup) calls `io->init_per_thread(&scan_ctx[i], config)` then `pthread_create(&senders[i], NULL, io->tx_thread, &scan_ctx[i])`. **Adding DPDK is purely: add a new vtable, add a `case IO_ENGINE_DPDK:` branch, register the constant in `scanner_defs.h`, and teach `conf.c` to recognize `--io-engine=dpdk`.** The dispatch refactor PR #65 §2.3 fixed is already paid off.

### 2.3 The packet construction surface (shared with all I/O engines)

`src/net.c` provides `create_syn_packet`, `create_udp_packet`, `create_icmp_packet`, `calculate_ip_checksum`, `calculate_tcp_checksum`, `calculate_icmp_checksum`. `src/send-afxdp.c:394-404,471-492` shows how to build a packet directly into an mbuf-equivalent (UMEM frame) using these helpers. **DPDK reuses the same helpers verbatim** — the only difference is the storage is `rte_mbuf->buf_addr + RTE_PKTMBUF_HEADROOM` instead of `umem_area + frame_id*frame_size`.

### 2.4 The BlackRock + rate-limit invariants (shared with all I/O engines)

`src/sender.c:32-57` (`rate_limit_batch`) and `src/send-afxdp.c:413-548` (per-batch BlackRock walk + blacklist + alive-queue filter) — DPDK preserves these bit-for-bit. Reuse `blackrock_shuffle`, `is_blacklisted`, `IS_IP_ALIVE`, `rate_limit_batch`, `xorshift32` unchanged. The TX/RX descriptor swap and the EAL bring-up are the only DPDK-specific moves.

### 2.5 How AnyScan invokes the scanner today

- `vulnscanner-zmap-adapter.py` (in this repo) builds argv from a JSON invocation; `resolve_io_engine()` (`vulnscanner-zmap-adapter.py:135`) emits `--io-engine={af_packet,af_xdp}` based on `ANYSCAN_SCANNER_IO_ENGINE` env, gated on `ANYSCAN_AF_XDP_AVAILABLE`.
- `install-external-deps.sh` (this repo) clones `AnyVM-Tech/anyscan-engine-c` and runs `make` with `USE_AF_XDP="${ANYSCAN_USE_AF_XDP:-0}"` (PR #71).
- `package-worker-bundle.sh:342` (this repo) has `rebuild_scanner_with_afxdp` which force-rebuilds when a cached AF_PACKET-only binary is present and `ANYSCAN_USE_AF_XDP=1`. PR #71 is the canonical pattern.
- `deploy.sh:108-150` (this repo) installs the produced binary; mirrors the same env-knob plumbing.

**DPDK Phase 2 mirrors PR #71's wire-up shape:** add `ANYSCAN_USE_DPDK` (build-time) and `ANYSCAN_DPDK_AVAILABLE` (install-time probe) with the same three-script chain plus a fourth — `tools/setup-dpdk.sh` (idempotent + reversible) for hugepages + `vfio-pci` bind, since DPDK has prerequisites AF_XDP does not.

---

## 3. Proposed architecture

### 3.1 File layout (engine repo: `AnyVM-Tech/anyscan-engine-c`)

Two new C files, one new internal header, modifications to four existing files. Mirrors the AF_XDP shape (PR #65 §3.1).

| File                                | Purpose                                                                                                                | Est. LOC |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------|----------|
| `src/send-dpdk.c`                   | `dpdk_sender_thread`: lcore pinning, mbuf pool acquire, TX-burst loop, mbuf template + per-packet IP/TCP/UDP patching. | ~380     |
| `src/recv-dpdk.c`                   | `dpdk_receiver_thread`: RX-burst poll, hand-off to existing `process_packet`, mbuf free.                                | ~180     |
| `include/dpdk-defs.h`               | Internal sizing constants (TX/RX ring depth, mbuf pool size, mempool cache size), opaque `struct dpdk_state` fwd-decl, EAL bring-up state.    | ~80      |
| `src/dpdk-eal.c`                    | One-shot, process-wide EAL initialization (`rte_eal_init` argv synthesis, port probe, mempool create, port `rte_eth_dev_configure` + queue setup + `rte_eth_dev_start`). Called from `main.c` BEFORE `setup_scan` when the engine is DPDK. | ~250     |
| `src/engine.c` (modify)             | New `case IO_ENGINE_DPDK:` in `pick_io_engine`; `io_engine_dpdk` vtable definition under `#ifdef USE_DPDK`.            | ~40 (delta) |
| `include/scanner_defs.h` (modify)   | Add `IO_ENGINE_DPDK = 3`; add DPDK-specific fields to `thread_context_t` under `#ifdef USE_DPDK` (port id, queue id, mbuf pool ptr).  | ~25 (delta) |
| `include/scanner.h` (modify)        | Declare `dpdk_sender_thread`, `dpdk_receiver_thread`, `dpdk_init_per_thread`, `dpdk_teardown_per_thread`, `dpdk_eal_bringup`, `dpdk_eal_teardown` under `#ifdef USE_DPDK`. | ~10 (delta)  |
| `src/main.c` (modify)               | Pre-`parse_arguments` argv slicing for `--dpdk-eal=...`; post-`parse_arguments` `dpdk_eal_bringup(config)` call when `io_engine == IO_ENGINE_DPDK`. | ~30 (delta) |
| `src/conf.c` (modify)               | Extend `io_engine_from_string` and `io_engine_name` to recognize `dpdk`; reject `--io-engine=dpdk` at parse time when `USE_DPDK` is unset (mirroring the existing `USE_AF_XDP` block in `conf.c:179-185`). New CLI flags: `--dpdk-eal-args=<string>` (raw EAL argv, default empty), `--dpdk-port=<idx>` (default 0), `--dpdk-num-rxq=<N>` / `--dpdk-num-txq=<N>` (default = senders/receivers). | ~50 (delta) |
| `Makefile` (modify)                 | `USE_DPDK=1` conditional that adds `-DUSE_DPDK`, `pkg-config --cflags libdpdk` / `pkg-config --libs libdpdk`, and the new `.c` files. Mirrors the existing `USE_AF_XDP` block.   | ~15 (delta) |
| `tests/dpdk_dispatch.sh`            | Smoke test for `--io-engine=dpdk` CLI parsing + the "binary not built with USE_DPDK=1" error path. Mirrors `tests/io_engine_dispatch.sh`. | ~40      |

**Estimated total in the engine repo: ~1,100 LOC (~860 net new + ~140 in modified files).** Larger than AF_XDP's 580 LOC because:

1. **EAL bring-up is non-trivial and process-wide**, not per-thread (`src/dpdk-eal.c`, ~250 LOC). AF_XDP needed no analog — `xsk_socket__create` is a per-thread call.
2. **mbuf pool + port + queue setup is verbose** vs. AF_XDP's `xsk_socket__create` one-liner. The DPDK init-per-thread is shorter than AF_XDP's (mbuf pool is process-wide, queues are pre-configured), but the EAL side absorbs the difference.
3. **No libxdp-grade convenience library**. DPDK is closer to the metal API.

| File (this repo: `AnyVM-Tech/AnyScan`)                         | Purpose                                                                                                  | Est. LOC |
|---------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|----------|
| `tools/setup-dpdk.sh` (new)                                   | Idempotent + reversible host setup: hugepages allocation (1 GB or 2 MB pages), `vfio-pci` module load, NIC PCI BDF bind, `--unbind` reverse path. | ~180     |
| `install-external-deps.sh` (modify)                           | Add `ANYSCAN_USE_DPDK` env knob, `binary_has_dpdk_linkage()` linkage probe (mirrors `binary_has_afxdp_linkage`), `vulnscanner_make_args()` extension. | ~50 (delta) |
| `package-worker-bundle.sh` (modify)                           | Mirror PR #71's `rebuild_scanner_with_afxdp` shape with a `rebuild_scanner_with_dpdk` helper; record `use_dpdk` in `README.txt`. | ~60 (delta) |
| `deploy.sh` (modify)                                          | Mirror PR #71's `install_vulnscanner_binary` env-knob plumbing for `ANYSCAN_USE_DPDK`. | ~30 (delta) |
| `runtime.worker.env.template` (modify)                        | Document `ANYSCAN_USE_DPDK` (build-time), `ANYSCAN_DPDK_AVAILABLE` (install-time probe), `ANYSCAN_DPDK_PCI_BDFS` (which BDFs to bind), `ANYSCAN_DPDK_HUGEPAGES_GB` (hugepages reservation). | ~25 (delta) |
| `vulnscanner-zmap-adapter.py` (modify)                        | Extend `SUPPORTED_IO_ENGINES = ("af_packet", "af_xdp", "dpdk")`; gate `dpdk` on `ANYSCAN_DPDK_AVAILABLE`; emit `--dpdk-port=` and `--dpdk-eal-args=` based on env. | ~40 (delta) |
| `install-worker-bundle.sh` (modify)                           | Add `probe_dpdk_runtime_available()`: checks `lsmod \| grep vfio_pci`, `/sys/kernel/mm/hugepages/*` non-empty, `ldconfig -p \| grep librte_eal`. Writes `ANYSCAN_DPDK_AVAILABLE=true\|false`. | ~50 (delta) |
| `tools/test-install-external-deps-dpdk.sh` (new)              | Bash unit-test mirror of `tools/test-install-external-deps-afxdp.sh` (PR #71): assertions across 4 cases (default off, USE_DPDK=1 missing scanner, USE_DPDK=1 cached non-DPDK binary, USE_DPDK=1 cached DPDK-linked binary). | ~330     |

**Estimated total in this repo: ~765 LOC (~510 net new + ~255 in modified files).**

**Grand total Phase 2: ~1,865 LOC** (engine + AnyScan). Compare to PR #65's 580 LOC AF_XDP estimate — ~3.2× the scope. This matches the brief's assessment ("DPDK has the highest theoretical ceiling … but the largest engineering scope").

### 3.2 Where DPDK slots in (architecture diagram)

```
        ┌──────────────────────────────────────────────────────────────┐
        │  main.c                                                       │
        │   ▼                                                           │
        │  argv pre-scan → split into eal_argv[] and scanner_argv[]     │  ◄── new
        │   ▼                                                           │
        │  parse_arguments(scanner_argv) → config.io_engine             │
        │   ▼                                                           │
        │  if config.io_engine == IO_ENGINE_DPDK:                       │
        │      dpdk_eal_bringup(config, eal_argv)  ────┐                │  ◄── new
        │   ▼                                          ▼                │
        │  setup_scan(config) → run_scan(config)                        │
        │   ▼                                                           │
        │  io = pick_io_engine(config.io_engine)  // existing dispatch  │
        │   ▼                                                           │
        │  for i in senders:                                            │
        │      io.init_per_thread(scan_ctx[i], config)  ──┐             │
        │      pthread_create(senders[i], io.tx_thread)   │             │
        │   ▼                                              ▼            │
        │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐   │
        │  │ AF_PACKET    │ │ AF_XDP       │ │ DPDK (USE_DPDK)      │   │
        │  │ sender.c     │ │ send-afxdp.c │ │ send-dpdk.c          │   │
        │  │  PF_PACKET   │ │  XSK + UMEM  │ │  rte_eth_tx_burst    │   │
        │  │  TX_RING     │ │  NEED_WAKEUP │ │  per-lcore mempool   │   │
        │  │  sendto kick │ │  sendto kick │ │  no kernel syscall   │   │
        │  └──────────────┘ └──────────────┘ └──────────────────────┘   │
        │             ▼                              ▼                  │
        │  shared above the I/O boundary: net.c (packet build),         │
        │  blackrock, rate_limit_batch, blacklist filter, alive-queue,  │
        │  stats. DPDK is purely a TX/RX descriptor swap + EAL bring-up.│
        └──────────────────────────────────────────────────────────────┘
```

The four paths share **everything above the I/O socket boundary**: packet construction, BlackRock shuffle, rate limiting, blacklist filter, alive-queue, stats. DPDK's only distinguishing feature beyond AF_XDP is the EAL bring-up (single-threaded, process-wide, before `setup_scan`).

### 3.3 Engine vtable slot

Add to `src/engine.c` under `#ifdef USE_DPDK`:

```c
#ifdef USE_DPDK
const io_engine_vtable_t io_engine_dpdk = {
    .name                = "dpdk",
    .init_per_thread     = dpdk_init_per_thread,
    .tx_thread           = dpdk_sender_thread,
    .rx_thread           = dpdk_receiver_thread,
    .teardown_per_thread = dpdk_teardown_per_thread,
};
#endif /* USE_DPDK */
```

Add `case IO_ENGINE_DPDK:` to `pick_io_engine` mirroring the `IO_ENGINE_AF_XDP` arm. Add `IO_ENGINE_DPDK = 3` to `scanner_defs.h:61-63` (next slot after `IO_ENGINE_AF_XDP = 2`). Add `dpdk_*` declarations to `scanner.h` under `#ifdef USE_DPDK`. Extend `io_engine_from_string` / `io_engine_name` in `conf.c:30-45`.

### 3.4 EAL bring-up sequencing (the non-trivial part)

DPDK requires `rte_eal_init` to be called once per process, before any DPDK API. EAL takes its own argv (`-l <core list>`, `--socket-mem ...`, `-a <BDF>` to allow specific PCI devices, `-n <memory channels>`). Rather than parse-and-passthrough every flag, we adopt the standard DPDK pattern: split the scanner's argv on `--` so everything **before** `--` is scanner args and everything **after** `--` is EAL args. To avoid surprising users who don't run DPDK, we only do the split when `--io-engine=dpdk` is present in the scanner argv; otherwise argv is left untouched.

```
./scanner --interface=eth1 --rate=20M --io-engine=dpdk -- -l 0-7 --socket-mem 1024 -a 0000:00:06.0 -a 0000:00:07.0
              \________________________________________/    \___________________________________________________/
                          scanner argv                                          EAL argv
```

`src/main.c` modifications:

1. Pre-`parse_arguments`: scan argv for `--io-engine=dpdk`. If found, locate `--`, split argv at that position. Stash the EAL slice for later.
2. `parse_arguments` runs against the truncated scanner argv (the existing `getopt_long` loop is unmodified).
3. After `parse_arguments`, if `config.io_engine == IO_ENGINE_DPDK`, call `dpdk_eal_bringup(config, eal_argv, eal_argc)` which:
   - Calls `rte_eal_init(eal_argc, eal_argv)`.
   - Probes `rte_eth_dev_count_avail()`. Logs which BDFs DPDK sees.
   - For each port to use (default: just the first; configurable via `--dpdk-port=`), calls `rte_eth_dev_configure(port, num_rxq, num_txq, &port_conf)`.
   - Creates one process-wide mbuf pool: `rte_pktmbuf_pool_create("scanner_mbufs", 8192*senders, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id())`.
   - For each TX/RX queue: `rte_eth_tx_queue_setup`, `rte_eth_rx_queue_setup`.
   - `rte_eth_dev_start(port)`. Logs link state.
4. After `run_scan`, `dpdk_eal_teardown` calls `rte_eth_dev_stop`, `rte_eth_dev_close`, `rte_eal_cleanup`.

**This is the main architectural divergence from AF_XDP.** AF_XDP needs no analog — `xsk_socket__create` is per-thread and self-contained. DPDK separates "process is now a DPDK app" (EAL init, ports configured, queues set up, mempool live) from "this thread is going to run a TX burst loop on queue N" (per-thread init: just stash port id + queue id + mempool ptr in `thread_context_t`).

### 3.5 Per-thread DPDK setup

`dpdk_init_per_thread` is shorter than `afxdp_tx_init_per_thread` (`src/send-afxdp.c:265-335`) because the process-wide work was already done in `dpdk_eal_bringup`. It just:

1. Stashes `ctx->dpdk = { .port_id = config->dpdk_port_id, .queue_id = ctx->thread_id, .mbuf_pool = g_mbuf_pool }`.
2. (Optional) `rte_lcore_id()` sanity check — DPDK threads should be running on the lcore they were registered for. The scanner currently spawns sender threads with `pthread_create` and pins via `pthread_setaffinity_np` (`src/sender.c:62-65`); we do the same here, with the lcore index matching the queue id 1:1.

### 3.6 TX-burst loop pattern (the `dpdk_sender_thread` body)

Reference: [DPDK `examples/l2fwd/main.c::l2fwd_main_loop`](https://github.com/DPDK/dpdk/blob/main/examples/l2fwd/main.c) and [`examples/skeleton/basicfwd.c::lcore_main`](https://github.com/DPDK/dpdk/blob/main/examples/skeleton/basicfwd.c).

```c
void *dpdk_sender_thread(void *arg) {
    thread_context_t *ctx = arg;
    struct dpdk_state *s = ctx->dpdk;
    /* Build the per-thread template packet (same as send-afxdp.c:394-404). */
    packet_t scan_pkt;
    if (ctx->config->scan_method == SCAN_METHOD_UDP) create_udp_packet(&scan_pkt, ...);
    else if (...) ...

    struct rte_mbuf *bufs[BATCH_SIZE];
    while (ctx->running && !stop_signal && ctx->work.current_global_idx < ctx->work.global_end_idx) {
        if (rte_pktmbuf_alloc_bulk(s->mbuf_pool, bufs, BATCH_SIZE) != 0) {
            /* mempool exhausted — TX hasn't drained yet. brief usleep + retry. */
            usleep(10);
            continue;
        }

        int built = 0;
        for (built = 0; built < BATCH_SIZE && ctx->work.current_global_idx < ctx->work.global_end_idx; built++) {
            uint64_t index = blackrock_shuffle(&ctx->config->blackrock, ctx->work.current_global_idx++);
            /* ... resolve ip_idx / port_idx / blacklist filter — same as send-afxdp.c:428-450 ... */
            unsigned char *pkt_data = rte_pktmbuf_mtod(bufs[built], unsigned char *);
            memcpy(pkt_data, scan_pkt.buffer, scan_pkt.length);
            /* ... patch dst-IP, src-port, TCP/UDP/ICMP fields, recompute checksums — same as
                 send-afxdp.c:467-492 ... */
            bufs[built]->data_len = bufs[built]->pkt_len = scan_pkt.length;
        }

        /* Free unused mbufs from the bulk-alloc tail (when blacklist filter skipped some). */
        for (int i = built; i < BATCH_SIZE; i++) rte_pktmbuf_free(bufs[i]);

        uint16_t sent = 0;
        while (sent < built && !stop_signal) {
            uint16_t n = rte_eth_tx_burst(s->port_id, s->queue_id, bufs + sent, built - sent);
            sent += n;
            if (n == 0) break;  /* port-level backpressure; spin briefly */
        }
        if (sent < built) {
            /* Same "rollback current_global_idx + free unsent mbufs" pattern as
             * send-afxdp.c:528-548 — without it, sustained TX backpressure
             * silently drops scan targets. */
            for (int i = sent; i < built; i++) rte_pktmbuf_free(bufs[i]);
            ctx->work.current_global_idx -= (built - sent);
        }
        atomic_fetch_add(&ctx->stats->packets_sent, sent);
        rate_limit_batch(ctx, sent);
    }
    return NULL;
}
```

The frame-recycling pattern AF_XDP needs (`afxdp_drain_completion_ring` / free-stack) does **not** apply: DPDK's TX path takes ownership of the mbuf and the PMD frees it back to the mempool when the NIC finishes the descriptor. From the scanner's POV, mbufs are allocated, filled, submitted, and forgotten. This is one of DPDK's ergonomic advantages over AF_XDP.

### 3.7 RX path

`dpdk_receiver_thread` is the simplest of the four engines. Mirrors `recv-afxdp.c` shape:

```c
void *dpdk_receiver_thread(void *arg) {
    thread_context_t *ctx = arg;
    struct dpdk_state *s = ctx->dpdk;
    struct rte_mbuf *bufs[BATCH_SIZE];
    while (ctx->running && !stop_signal) {
        uint16_t n = rte_eth_rx_burst(s->port_id, s->queue_id, bufs, BATCH_SIZE);
        for (uint16_t i = 0; i < n; i++) {
            const uint8_t *data = rte_pktmbuf_mtod(bufs[i], const uint8_t *);
            uint16_t len = rte_pktmbuf_pkt_len(bufs[i]);
            process_packet(data, len, ctx->stats, ctx->config, ctx->src_ip);
            rte_pktmbuf_free(bufs[i]);
        }
        if (n == 0) rte_delay_us(1);  /* yield briefly when idle */
    }
    return NULL;
}
```

`process_packet` is reused unchanged (`src/receiver.c` exports it). RSS distribution is configured at port-setup time — `rte_eth_dev_configure` with `ETH_MQ_RX_RSS` and a key matching the kernel default — so reply traffic spreads evenly across the RX queues we've set up.

### 3.8 ENA / AWS specifics

- **ENA PMD support**: in mainline DPDK as `net_ena`. Built into `librte_net_ena.so`. No Amazon-only patches needed for c6in.metal.
- **NIC binding**: scanner ENIs (eth1..eth7) get unbound from the kernel ENA driver and bound to `vfio-pci` via the `tools/setup-dpdk.sh` script (§3.10). eth0 stays on kernel networking for the agentd control-plane heartbeat.
- **Multi-queue**: ENA supports multiple TX/RX queues per ENI on c6in.metal (typically 8–32 queues per NIC depending on instance size). DPDK uses these directly without the AF_XDP "lower-half-channels" constraint.
- **PCI BDF discovery**: at install time, `tools/setup-dpdk.sh` walks `/sys/class/net/<iface>/device` to map kernel iface names to PCI BDFs. Operators specify either iface names or BDFs; the script resolves either to a BDF before the bind step.
- **Hugepages**: DPDK on ENA needs at minimum ~1 GB of hugepages per port for the mbuf pool + TX/RX descriptor rings + mempools. `tools/setup-dpdk.sh` reserves 4 × 1 GB pages by default (configurable via `ANYSCAN_DPDK_HUGEPAGES_GB`); c6in.metal has 192 GiB RAM so 4 GiB hugepages is negligible.
- **No ARP**: DPDK has no kernel ARP table. The scanner already accepts `--gateway-mac=AA:BB:...` (`src/conf.c:144-151`). For DPDK mode, we make this **mandatory at parse time** if `io_engine == IO_ENGINE_DPDK` and `gateway_set == 0`. The error message points at the existing `--gateway-mac` flag and `arping <gateway_ip>` for resolution. Phase 2 may add an `--arp-resolve` helper that does an out-of-band kernel-stack ARP lookup before EAL bring-up; deferred.

### 3.9 Build-system integration (engine repo)

Append to engine `Makefile`, mirroring the existing `USE_AF_XDP` block:

```make
# DPDK userspace-networking I/O engine — Phase 2 of the DPDK integration plan
# (AnyVM-Tech/AnyScan plans/2026-04-28-portscan-dpdk-impl-v1.md, §3.9).
#
# `make USE_DPDK=1` adds the DPDK send/recv/EAL translation units to the build,
# defines USE_DPDK so the io_engine_dpdk vtable is registered in engine.c, and
# links librte_eal + librte_ethdev + librte_mbuf + librte_mempool + librte_net
# + librte_net_ena via pkg-config. Default build (USE_DPDK unset) is bit-for-bit
# identical to upstream — the DPDK source files are wrapped in #ifdef USE_DPDK
# so they compile to nothing when the flag is off, and the vtable registration
# in engine.c degrades to a "rebuild with USE_DPDK=1" error message if the
# operator passes --io-engine=dpdk at runtime.
#
# pkg-config is the supported configuration source for libdpdk flags
# (libdpdk.pc is shipped by libdpdk-dev on Debian/Ubuntu and by `make install`
# in source builds). We do NOT fall back to explicit -l flags because DPDK's
# library names embed version numbers (e.g. -lrte_eal -lrte_eal_22 etc.) and
# the explicit form is not portable across distros. If pkg-config is missing
# the build fails loudly, which is the right escalation.
ifeq ($(USE_DPDK),1)
    CFLAGS += -DUSE_DPDK
    DPDK_PKG_CFLAGS := $(shell pkg-config --cflags libdpdk)
    DPDK_PKG_LIBS   := $(shell pkg-config --libs   libdpdk)
    ifeq ($(strip $(DPDK_PKG_LIBS)),)
        $(error libdpdk pkg-config not found — install libdpdk-dev or build DPDK with --prefix and set PKG_CONFIG_PATH)
    endif
    CFLAGS  += $(DPDK_PKG_CFLAGS)
    LDFLAGS += $(DPDK_PKG_LIBS)
    SRCS += src/send-dpdk.c src/recv-dpdk.c src/dpdk-eal.c
endif
```

Mutually compatible with `USE_AF_XDP=1` and `USE_PFRING_ZC=1` at compile time but mutually exclusive at runtime (selected by `--io-engine=`). The same binary can ship with all three engines linked.

### 3.10 AnyScan-side wire-up (this repo)

Mirrors PR #71's pattern (`fix(build): wire ANYSCAN_USE_AF_XDP=1 through install-external-deps + package-worker-bundle + deploy`).

#### 3.10.1 `install-external-deps.sh`

- Add `ANYSCAN_USE_DPDK="${ANYSCAN_USE_DPDK:-0}"` env knob (mirrors `ANYSCAN_USE_AF_XDP` at lines 23-27).
- Add `binary_has_dpdk_linkage()` that runs `ldd "$bin" | grep -q librte_eal` (mirrors `binary_has_afxdp_linkage`).
- Extend `vulnscanner_make_args()` to emit `USE_DPDK=1` when `ANYSCAN_USE_DPDK=1` (cumulative with `USE_AF_XDP=1`).
- Best-effort `apt-get install -y libdpdk-dev` block that mirrors the AF_XDP one (lines 71-113 in current `install-external-deps.sh`); skip silently if apt-get unavailable so source-built DPDK installs still work.
- The cache-staleness check at line 160 widens: if `ANYSCAN_USE_DPDK=1` and the cached binary lacks DPDK linkage, force `make clean && make USE_DPDK=1 [USE_AF_XDP=1]`.

#### 3.10.2 `package-worker-bundle.sh`

- New `rebuild_scanner_with_dpdk` helper that fires `make USE_DPDK=1` in the engine repo when the cached binary is missing or non-DPDK-linked. Mirrors `rebuild_scanner_with_afxdp` at line 342.
- The `README.txt` recorded per bundle gains a `use_dpdk: 0|1` field.

#### 3.10.3 `deploy.sh`

- Mirror the env-knob plumbing in `install_vulnscanner_binary` (line 108): a stale non-DPDK binary is removed when `ANYSCAN_USE_DPDK=1` so the rebuild branch fires; final post-build assertion bails if the produced binary still lacks `librte_eal` linkage (likely a missing `libdpdk-dev`).

#### 3.10.4 `runtime.worker.env.template`

Append after the AF_XDP block (currently ends at line 165):

```
# DPDK userspace-networking I/O engine. Phase 2 of plans/2026-04-28-portscan-dpdk-impl-v1.md.
# DPDK is opt-in per worker and is only honored when:
#   1. ANYSCAN_DPDK_AVAILABLE=true, which install-worker-bundle.sh writes
#      after probing librte_eal.so loadable + vfio_pci kernel module +
#      hugepages reserved at /sys/kernel/mm/hugepages/*; AND
#   2. tools/setup-dpdk.sh has been run successfully, binding the listed
#      ENIs to vfio-pci and reserving hugepages.
# When ANYSCAN_SCANNER_IO_ENGINE=dpdk is requested but ANYSCAN_DPDK_AVAILABLE
# is false, the adapter falls back to af_packet (loud warning, audit trail).
# ANYSCAN_SCANNER_IO_ENGINE=af_packet
#
# Build-time DPDK opt-in (read by install-external-deps.sh,
# package-worker-bundle.sh, deploy.sh — NOT by the agentd runtime).
# ANYSCAN_USE_DPDK=0
#
# DPDK NIC binding. Comma-separated PCI BDFs (e.g. "0000:00:06.0,0000:00:07.0")
# OR comma-separated kernel iface names (e.g. "eth1,eth2"); tools/setup-dpdk.sh
# resolves iface names to BDFs at bind time. Skip rule: tools/setup-dpdk.sh
# refuses to bind eth0 (the agentd control-plane interface) and refuses to bind
# the only NIC in a single-NIC instance, so eth0 always retains kernel networking.
# ANYSCAN_DPDK_PCI_BDFS=
#
# DPDK hugepages reservation. Default 4 GB (4 × 1 GB or 2048 × 2 MB). c6in.metal
# has 192 GiB so 4 GB is a rounding error; Phase 2 micro-bench may adjust.
# ANYSCAN_DPDK_HUGEPAGES_GB=4
```

#### 3.10.5 `tools/setup-dpdk.sh` (new, ~180 LOC)

Idempotent + reversible. Two subcommands:

- `tools/setup-dpdk.sh bind` — read `ANYSCAN_DPDK_PCI_BDFS` and `ANYSCAN_DPDK_HUGEPAGES_GB`, resolve iface names to BDFs, reserve hugepages (`echo N > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages` or fallback to 2 MB), `modprobe vfio-pci`, `dpdk-devbind.py --bind=vfio-pci <BDF>`. Refuses to bind eth0 or the only NIC. Logs "already bound" and exits 0 if already in correct state (idempotent).
- `tools/setup-dpdk.sh unbind` — reverse: `dpdk-devbind.py --bind=ena <BDF>`, free hugepages, leave `vfio-pci` module loaded (other consumers may need it).

The `dpdk-devbind.py` script ships with `dpdk` (Debian/Ubuntu) at `/usr/share/dpdk/usertools/dpdk-devbind.py`. Pre-flight check that the script is present; document the path in the script header.

#### 3.10.6 `vulnscanner-zmap-adapter.py`

Extend the constant block at line 132:

```python
SUPPORTED_IO_ENGINES = ("af_packet", "af_xdp", "dpdk")
DEFAULT_IO_ENGINE = "af_packet"
```

Extend `resolve_io_engine()` at line 135 with the DPDK gating check (mirrors the AF_XDP check at line 156-164):

```python
    if requested == "dpdk" and not env_flag("ANYSCAN_DPDK_AVAILABLE"):
        print("[anyscan-adapter] ... falling back to af_packet", file=sys.stderr)
        return DEFAULT_IO_ENGINE
```

When the engine is `dpdk`, the adapter additionally appends `--dpdk-port=0` (or from env) and the EAL passthrough `-- -l <core list> --socket-mem ...` after the scanner argv. The EAL argv assembly logic is small (~30 LOC) and is the only DPDK-aware part of the Python adapter.

### 3.11 NIC binding decision (the question the brief explicitly asked)

> Decide bind-PMD-to-NICs-at-runtime (loses kernel netstack on those NICs) vs dedicated-DPDK-NIC (requires adding NICs).

**Recommendation: dedicated-DPDK-NIC.**

Rationale:

1. **agentd needs kernel networking on eth0.** The control-plane heartbeat, remote-update channel, journal shipping, and `runtime.env` fetch all use the kernel TCP stack. Binding eth0 to `vfio-pci` would cut the worker off from the orchestrator. PR #63 already flagged this constraint.
2. **c6in.metal already has 8 ENIs.** ENIs eth1..eth7 are scan-only (anygpt-4 multi-NIC bench shape). Binding seven NICs to `vfio-pci` while leaving eth0 on the kernel is a clean partition. No new NICs need to be added; the "requires adding NICs" framing in the brief comes from non-c6in.metal instance shapes that may have only one NIC.
3. **Single-NIC instance shapes** (anything below `c6in.metal` with <2 ENIs) are explicitly **not eligible for DPDK mode** in v1. The skip rule lives in `tools/setup-dpdk.sh` (refuses to bind eth0; refuses to bind the only NIC) AND in `install-worker-bundle.sh::probe_dpdk_runtime_available` (sets `ANYSCAN_DPDK_AVAILABLE=false` if NIC count < 2). This degrades cleanly to AF_XDP or AF_PACKET on those tiers — no operator-visible failure.
4. **Bind-at-runtime would force a complex "swap eth1 from kernel to DPDK then back" dance** for every scan, with the kernel routing table changing under live agentd. Not worth the complexity for a gain that the dedicated-DPDK-NIC pattern already realizes on c6in.metal.

The trade-off: tiers without ≥2 ENIs are DPDK-ineligible. That is the correct answer. The whole point of DPDK on AnyScan is to break the per-NIC ceiling on c6in.metal (which has plenty of NICs); on smaller tiers the AF_PACKET / AF_XDP ceiling is not the bottleneck.

---

## 4. Dependency surface

### 4.1 Build-time

| Package        | Min version | Purpose                                  | Notes                                                                                          |
|----------------|-------------|------------------------------------------|------------------------------------------------------------------------------------------------|
| `libdpdk-dev`  | 22.11       | DPDK headers + `libdpdk.pc` for `pkg-config` | Ubuntu 24.04 ships 22.11 LTS in main. Ubuntu 22.04 ships 21.11 (works but older PMDs); Debian bookworm ships 22.11. |
| `pkg-config`   | any         | Resolve libdpdk include / link flags     | Universally available.                                                                        |
| `python3`      | any         | `dpdk-devbind.py` bind/unbind tool       | Already a host requirement.                                                                   |
| `linux-headers-$(uname -r)` | host kernel | Only if compiling kernel-mode UIO; we use `vfio-pci` (in-tree), so **NOT REQUIRED**. | —     |

**Recommended baseline AMI: Ubuntu 24.04 (Noble) — same as the AF_XDP plan.** `libdpdk-dev` is in main on 24.04; on 22.04 we'd need to either accept the older 21.11 PMDs or build DPDK from source (a 30-min operation we'd want to do once at AMI-bake time, not per-deploy).

### 4.2 Runtime (already-deployed bundle install)

Add to the worker-bundle install path:

**Ubuntu 24.04 (Noble):**

```bash
apt-get install -y --no-install-recommends \
    libdpdk23 dpdk
```

`libdpdk23` is the runtime shared-library package (suffix is the SONAME major version on 24.04); `dpdk` carries `dpdk-devbind.py` and `dpdk-hugepages.py`. Both are universe on Noble; the install-deps script needs to enable universe before the apt-get install (a one-line `add-apt-repository universe` in the existing apt block).

**Ubuntu 22.04 (Jammy) / Debian bookworm fallback (if needed):**

```bash
apt-get install -y --no-install-recommends \
    libdpdk21 dpdk
```

The package-name suffix is the SONAME major version, which differs between distros. The defensive install pattern is to try the Noble name and fall back to the Jammy name if it 404s — same shape PR #71 introduced for the `libelf1`/`libelf1t64` rename.

### 4.3 Kernel feature checks

Phase 2 must add a runtime probe on scanner startup (when `--io-engine=dpdk`) AND at install time (`install-worker-bundle.sh::probe_dpdk_runtime_available`):

1. `lsmod | grep vfio_pci` — module loaded.
2. `/sys/kernel/mm/hugepages/hugepages-{1048576,2048}kB/nr_hugepages` ≥ minimum — hugepages reserved. Minimum: `(senders × 256 mbufs × 2KB) + (mempool overhead) + 256 MB headroom` ≈ 1 GB for typical configs; install probe asserts ≥ `ANYSCAN_DPDK_HUGEPAGES_GB` × 1 GB.
3. `ldconfig -p | grep librte_eal` — DPDK runtime present.
4. `dpdk-devbind.py --status` returns at least one NIC bound to `vfio-pci`.
5. `uname -r` ≥ 5.4 (kernel `vfio-pci` is mature; AF_XDP's 5.10 minimum doesn't apply).

If any check fails, `ANYSCAN_DPDK_AVAILABLE=false` is written and the adapter falls back to `af_packet`. No silent failure modes.

### 4.4 Capabilities

DPDK with `vfio-pci` requires:

- `CAP_SYS_RAWIO` for `/dev/vfio/*` access (or, more cleanly, the `/dev/vfio/<group>` device made world-readable for the agentd user — the standard `udev` rule that ships with `dpdk` does this).
- `CAP_IPC_LOCK` for `mlock`-ing hugepages.
- `CAP_NET_ADMIN` for some PMD-internal operations.

Phase 2 systemd unit edit: `anyscan-worker.service` adds `AmbientCapabilities=CAP_SYS_RAWIO CAP_IPC_LOCK CAP_NET_ADMIN`. **Keeps existing `CAP_NET_RAW CAP_BPF`** (for AF_PACKET / AF_XDP fallback paths). Phase 2 task; out of scope to edit prod systemd in Phase 1.

### 4.5 Hugepages and `vfio-pci` — the install-time prerequisites

`tools/setup-dpdk.sh bind` is the install-time setup step. It is **idempotent** (safe to re-run; detects already-bound state) and **reversible** (`tools/setup-dpdk.sh unbind` returns the system to kernel networking). The reversal path is the rollback knob: if a DPDK canary goes wrong, an operator runs `tools/setup-dpdk.sh unbind` and the worker reverts to AF_PACKET / AF_XDP transparently.

`tools/setup-dpdk.sh` is invoked **once at install time** by `install-worker-bundle.sh` when `ANYSCAN_USE_DPDK=1` and the runtime probe passes. It is NOT invoked at scanner startup — DPDK setup is too heavyweight for that, and rebinding NICs every scan would create a massive risk surface.

---

## 5. Test plan

### 5.1 Synthetic loopback bench (Phase 2 task 1)

- Two `vmxnet3` NICs in a KVM VM, both bound to `vfio-pci`. Scanner sends with `--io-engine=dpdk` to one, receives via the other (no real loopback in DPDK without TAP indirection — the cleanest setup is two paired VMs or two NICs in one VM with a dummy bridge).
- Pass criteria: scanner-reported `packets_sent` rate ≥ 90% of theoretical for `vmxnet3` (~3-5 M pps).
- Regression criteria: `--io-engine=af_packet` (default) bit-for-bit unchanged from `main`.
- Alternative if `vmxnet3` is unavailable: `pcap_dump` virtual port. DPDK includes a `net_pcap` PMD that writes to a `.pcap` file; this gives us a "send 1 M packets, count packets in the .pcap" loopback that runs anywhere.

### 5.2 Unit-style verification (`tests/dpdk_dispatch.sh`, ~40 LOC)

- Mirror `tests/io_engine_dispatch.sh` for DPDK: assertions that `--io-engine=dpdk` parses cleanly, the "binary not built with USE_DPDK=1" error fires when DPDK is unset, the "binary not bound to any vfio-pci device" error fires when bind hasn't run.
- Does not require root or actual NICs.

### 5.3 Live `c6in.metal` bench (Phase 2 task 2)

- Single ENI bound to `vfio-pci`: rate ramp 1 M → 30 M pps in `--io-engine=dpdk`. Pass: sustains ≥15 M pps for 60s without `rte_eth_stats` showing TX errors.
- 4 ENIs: target ≥40 M pps aggregate (1.8× the AF_XDP `drv+copy` ceiling). Stretch: 60 M pps.
- 7 ENIs (eth1..eth7, eth0 retained): target ≥70 M pps aggregate. Stretch: 100 M pps (the brief's projection).
- Capture: `rte_eth_stats_get`, `ethtool -S <iface>` deltas (only on still-kernel NICs), host CPU per-core, observed scan completion time vs AF_XDP and AF_PACKET baselines.
- Compare: `anyscan_afxdp_ena_constraint` benchmark numbers (22 M pps aggregate in `drv+copy`) — DPDK target is 2-4× that.

### 5.4 Fallback regression

- `--io-engine=af_packet` (the default) must remain bit-for-bit identical to `main`. Same as PR #65.
- `--io-engine=af_xdp` must remain bit-for-bit identical to PR #65 / #71. Same CI smoke test.
- `--io-engine=dpdk` on a non-DPDK-prepared host (no hugepages, NICs still on kernel) must fail loudly at EAL init with a one-line error pointing at `tools/setup-dpdk.sh bind` and `--io-engine=af_xdp`/`af_packet` as fallbacks.

### 5.5 Bind/unbind regression

- `tools/setup-dpdk.sh bind` followed by `tools/setup-dpdk.sh unbind` returns the system to its starting state (`ip link show` shows the same NICs in the same state, hugepages reservation back to baseline).
- Re-running `bind` when already bound is a no-op (idempotency assertion in the tools-test script).
- `bind` refuses to bind eth0 (assert in the tools-test script).
- `bind` refuses to bind the only NIC (assert: synthesize a single-NIC environment in a netns or VM).

### 5.6 Adapter-level integration (Phase 2 task 3)

- `vulnscanner-zmap-adapter.py` gains `dpdk` in `SUPPORTED_IO_ENGINES`. Default unset → `af_packet` (zero behavior change).
- Multi-NIC orchestrator (`run_multi_nic_scanner` at `vulnscanner-zmap-adapter.py:783`) propagates `io_engine=dpdk` per child invocation; each child's EAL argv targets a different NIC's BDF.
- Verify: AIMD controller (anygpt-33 — read-only for this work) doesn't choke on the higher achievable rates. May need a one-line ceiling bump in coordination with anygpt-33.

### 5.7 `tools/test-install-external-deps-dpdk.sh` (~330 LOC, Phase 2 task)

Mirror `tools/test-install-external-deps-afxdp.sh` (PR #71). Four cases × ~3 assertions each:

1. `ANYSCAN_USE_DPDK=0` (default) → make argv has no `USE_DPDK=1` token.
2. `ANYSCAN_USE_DPDK=1` + missing scanner → `make USE_DPDK=1` fires.
3. `ANYSCAN_USE_DPDK=1` + cached non-DPDK binary → `make clean` followed by `make USE_DPDK=1`.
4. `ANYSCAN_USE_DPDK=1` + cached DPDK-linked binary → no rebuild.

---

## 6. Risk register

| Risk                                                     | Likelihood | Impact      | Mitigation                                                                                                        |
|----------------------------------------------------------|------------|-------------|-------------------------------------------------------------------------------------------------------------------|
| `vfio-pci` bind fails on prod ENI (driver locked)        | Low        | High        | `tools/setup-dpdk.sh bind` is idempotent and `unbind` reverses cleanly — rollback is one shell command.           |
| DPDK ENA PMD bug on c6in.metal kernel/firmware combo     | Medium     | High        | Live-bench on the exact prod AMI before flipping default. Keep AF_XDP as one-flag fallback (config flip, no code revert). |
| Hugepages exhaustion at scan time                        | Medium     | Medium      | `install-worker-bundle.sh::probe_dpdk_runtime_available` asserts hugepages count BEFORE DPDK is marked available; agentd refuses to schedule a DPDK scan if hugepages drop below threshold. |
| `--gateway-mac` not set, DPDK has no ARP                 | High (initial setup) | High | Parse-time assertion in `conf.c`: when `io_engine == IO_ENGINE_DPDK` and `gateway_set == 0`, error with a clear pointer at `--gateway-mac` and `arping`. |
| systemd unit missing `CAP_SYS_RAWIO` / `CAP_IPC_LOCK`    | High (initial deploy) | High | Phase 2 systemd-unit PR with the cap additions. Documented in `runtime.worker.env.template`.                     |
| EAL argv passthrough (`-- -l 0-7 ...`) collides with shell quoting in adapter | Medium | Medium | Adapter constructs the EAL argv via `subprocess.run(args=[...])` (list, not shell string) so quoting is safe. Test case in adapter unit tests. |
| `libdpdk-dev` not in apt for some distro                 | Low        | Low         | Source-build fallback documented in `install-external-deps.sh` (`./configure --prefix=/usr/local; make install`). 22.04 vs 24.04 SONAME suffix handled by the same defensive-install pattern PR #71 used. |
| AIMD controller cannot keep up with new pps ceiling      | High       | Medium      | Same risk as PR #65 §6; coordinate with anygpt-33 before flipping DPDK on by default. The DPDK ceiling is higher than AF_XDP's, so this risk is more acute. |
| Operator runs `bind` on the wrong NIC and bricks heartbeat | Medium    | High        | Hard refusal in `tools/setup-dpdk.sh` — eth0 is by-name protected. Refusal also when binding would leave zero kernel NICs. |
| DPDK process crashes leak hugepages                      | Low        | Medium      | EAL `rte_eal_cleanup` runs in main()'s exit path. systemd unit has `ExecStopPost=tools/setup-dpdk.sh reclaim-hugepages` (Phase 2 task) for crash recovery.         |
| Phase 2 LOC estimate slips (DPDK is bigger than AF_XDP)  | Medium     | Low         | Phase 2 split into 7 small PRs (§8) so one slip doesn't block the others. Each PR is independently buildable and AF_PACKET/AF_XDP-compatible.                                |

---

## 7. Effort estimate

Honest engineering time, assuming one experienced C / Linux-networking engineer with prior DPDK familiarity, working from this plan. Compare to PR #65's AF_XDP estimate of 6–8 days; DPDK is ~2× because of EAL bring-up + host setup script + larger LOC envelope.

| Phase 2 chunk                                                    | Effort     | Verification gate                                              |
|------------------------------------------------------------------|------------|----------------------------------------------------------------|
| 2a. Engine: vtable slot + IO_ENGINE_DPDK constant + conf.c flag  | 0.5 day    | `make` + AF_PACKET smoke unchanged; `--io-engine=dpdk` rejected at parse (clear error) when `USE_DPDK` unset. |
| 2b. Engine: `dpdk-defs.h` + `dpdk-eal.c` (EAL bring-up only)     | 2 days     | `make USE_DPDK=1` builds; running `--io-engine=dpdk` brings up EAL on a vfio-bound NIC and exits after `setup_scan` log line. No actual scan yet. |
| 2c. Engine: `send-dpdk.c` + `recv-dpdk.c`                        | 3 days     | Synthetic loopback bench (§5.1) passes. veth-equivalent (`net_pcap` PMD) shows BlackRock walk preserved.        |
| 2d. AnyScan: `install-external-deps.sh` + `package-worker-bundle.sh` + `deploy.sh` env knobs | 1 day | `tools/test-install-external-deps-dpdk.sh` passes 12 assertions (mirrors PR #71). |
| 2e. AnyScan: `tools/setup-dpdk.sh bind/unbind`                   | 1 day      | Bind/unbind regression test (§5.5) passes on a c6in.metal-class VM.                                              |
| 2f. AnyScan: `vulnscanner-zmap-adapter.py` + `runtime.worker.env.template` | 0.5 day | Adapter unit tests; manual `ANYSCAN_SCANNER_IO_ENGINE=dpdk` invocation with the rest mocked. |
| 2g. AnyScan: `install-worker-bundle.sh::probe_dpdk_runtime_available` + systemd cap edit | 0.5 day | `ANYSCAN_DPDK_AVAILABLE` set correctly on a prepared host; refused on an unprepared one. |
| 2h. Live `c6in.metal` bench + regression sweep                   | 2-3 days   | §5.3 pass criteria. Compare against `anyscan_afxdp_ena_constraint` baseline.                                     |
| 2i. Manual canary on a single c6in.metal worker                  | 2 days     | 48 h clean run watching `dmesg`, `rte_eth_stats`, hit-rate.                                                      |
| **Total**                                                        | **12-15 days** | —                                                                                                              |

This is the *implementation* envelope. Add 3-5 days for review, CI-flake hunting, and the gradual default-on rollout per tier. **Realistic total: 3-4 weeks.**

This matches PR #63's "2-3 weeks of focused work" assessment plus the AnyScan-side wire-up that PR #63 also flagged but didn't budget. PR #65's AF_XDP work has demonstrated that the AnyScan-side wire-up is not free (PR #71 was a separate ~700-LOC PR three weeks after the original plan landed).

---

## 8. Rollout plan

1. **This PR** lands in `AnyVM-Tech/AnyScan` `perf/portscan-dpdk-impl-plan` → `main` as a draft → ready-for-review → merged. Reference doc only.
2. **Phase 2a-c PRs** ship to `AnyVM-Tech/anyscan-engine-c` as three small PRs. Each AF_PACKET-compatible by default.
3. **Phase 2d-g PRs** ship to `AnyVM-Tech/AnyScan` as four small PRs. Each AF_PACKET/AF_XDP-compatible by default; DPDK code is opt-in via `ANYSCAN_USE_DPDK`.
4. **Phase 2h bench** runs on a fresh c6in.metal worker. Numbers go in a follow-up bench memo PR (mirrors PR #63's memo shape).
5. **AnyScan adapter PR** propagates `io_engine: dpdk` but **defaults to `af_packet`**. Worker bundle ships with DPDK code-paths present but disabled.
6. **Manual canary**: enable `--io-engine=dpdk` on a single c6in.metal worker via `runtime.env`. Run for 48 h, watch `dmesg`, `rte_eth_stats`, hit-rate. (Ops territory.)
7. **Gradual default-on**: after 48 h clean, flip the AnyScan worker bundle default to `dpdk` for c6in.metal tier specifically. Keep AF_PACKET / AF_XDP defaults for other tiers.
8. **AnyGPT submodule bump**: standard `chore: bump apps/anyscan submodule pointer` PR after each AnyScan release lands.

Rollback at any step is a one-shell-command `tools/setup-dpdk.sh unbind` plus a one-line config flip back to `--io-engine=af_xdp` or `af_packet`. The code path is opt-in by design, so revert is a config + setup change, not a code revert.

---

## 9. Open questions (do not block this plan PR)

1. **Per-NIC EAL argv shape under multi-NIC scanning.** When `run_multi_nic_scanner` (`vulnscanner-zmap-adapter.py:783`) spawns N child scanners (one per NIC), each child needs its own EAL argv (`-l <core slice>`, `-a <BDF>`). The cleanest design is the adapter passes an explicit core list per child; whether that list is hand-tuned or auto-derived from `nproc / num_nics` is a Phase 2 micro-bench question. Default: even split.
2. **DPDK + AF_XDP coexistence on the same scanner binary.** `make USE_DPDK=1 USE_AF_XDP=1` should produce a binary that supports both engines. `--io-engine=dpdk` requires hugepages + vfio-pci; `--io-engine=af_xdp` requires kernel networking. They cannot coexist on the same NIC at the same time (vfio-pci unbinds the kernel driver), but they CAN coexist on different NICs in the same instance. Validate at install time, not Phase 1.
3. **Hugepages reservation: 1 GB pages vs 2 MB pages.** 1 GB pages give better TLB performance but can fragment over long-running hosts. 2 MB pages are easier to allocate dynamically. Default: 1 GB on c6in.metal (where memory is plentiful); fall back to 2 MB if the 1 GB allocation fails. Confirm in §5.3 bench.
4. **DPDK upstream PMD version pinning.** Mainline DPDK on 22.11 LTS vs latest. 22.11 LTS is what 24.04 ships; tracking latest would mean source-builds at AMI-bake time. Recommendation: pin to 22.11 LTS for v1; revisit when 24.11 LTS becomes the distro default.
5. **`librte_net_ena` lifecycle quirks.** ENA PMD has historically had per-firmware quirks (e.g. NIC reset on certain LRO settings). Live-bench (§5.3) is the only way to discover them on the prod AMI. Phase 2 task 2h budget includes time for surprise-quirk diagnosis.
6. **Should we provide an `--arp-resolve` helper?** DPDK has no kernel ARP. The current proposal makes `--gateway-mac` mandatory in DPDK mode. A small helper that does an out-of-band kernel-stack ARP lookup before EAL bring-up would be ergonomic but is a Phase 3 nicety. Not blocking.

---

## 10. References

**DPDK API / examples**:
- [DPDK Programmer's Guide — EAL](https://doc.dpdk.org/guides/prog_guide/env_abstraction_layer.html) — `rte_eal_init` lifecycle, lcore model.
- [DPDK Programmer's Guide — Mempool](https://doc.dpdk.org/guides/prog_guide/mempool_lib.html), [Mbuf](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html) — packet buffer lifecycle (`rte_pktmbuf_alloc_bulk`, `rte_pktmbuf_free`, `rte_pktmbuf_mtod`).
- [DPDK Programmer's Guide — Poll Mode Drivers](https://doc.dpdk.org/guides/prog_guide/poll_mode_drv.html) — port/queue setup (`rte_eth_dev_configure`, `rte_eth_tx_queue_setup`, `rte_eth_rx_queue_setup`).
- [`examples/skeleton/basicfwd.c`](https://github.com/DPDK/dpdk/blob/main/examples/skeleton/basicfwd.c) — minimal RX/TX skeleton; canonical reference.
- [`examples/l2fwd/main.c`](https://github.com/DPDK/dpdk/blob/main/examples/l2fwd/main.c) — multi-port multi-queue forwarding loop.
- [`examples/pktgen-dpdk`](https://github.com/pktgen/Pktgen-DPDK) — reference traffic generator; closest in shape to a port scanner.

**ENA / AWS specifics**:
- [DPDK ENA PMD](https://doc.dpdk.org/guides/nics/ena.html) — supported features, configuration knobs, c5n/c6in compatibility.
- [`amzn-drivers` ENA RELEASENOTES](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/RELEASENOTES.md) — feature history; useful when correlating PMD bugs with kernel-driver versions.

**DPDK setup / vfio-pci**:
- [DPDK Linux GSG — vfio](https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html#vfio) — vfio-pci binding, IOMMU requirements, no-IOMMU mode for non-virtualized hosts.
- [`dpdk-devbind.py` source](https://github.com/DPDK/dpdk/blob/main/usertools/dpdk-devbind.py) — the bind/unbind tool we shell out to.
- [DPDK hugepages guide](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment).

**AnyScan / AnyVM-Tech internal**:
- PR #63 (`plans/2026-04-27-portscan-dpdk-scope-memo-v1.md`) — original DPDK scope memo; deferred recommendation. Superseded by this plan.
- PR #65 (`plans/2026-04-27-portscan-afxdp-plan-v1.md`) — AF_XDP plan; structural mirror for this plan.
- PR #71 (`fix(build): wire ANYSCAN_USE_AF_XDP=1 through install-external-deps + package-worker-bundle + deploy`) — build-flag wire-up template that `ANYSCAN_USE_DPDK` mirrors.
- `AnyVM-Tech/anyscan-engine-c` — engine repo. Specifically `src/engine.c:155-178` (`pick_io_engine`), `include/scanner.h:42-64` (`io_engine_vtable_t`), `src/conf.c:30-45,167-188` (`io_engine_from_string` and CLI), `src/send-afxdp.c:265-559` (the closest existing TX-loop reference), `Makefile` (`USE_AF_XDP` block to mirror).
- `vulnscanner-zmap-adapter.py:118,135-167,243` — adapter binary resolution and `resolve_io_engine`.
- `runtime.worker.env.template:130-165` — AF_XDP env-knob template to mirror.
- Memory record `anyscan_afxdp_ena_constraint` — the c6in.metal AF_XDP bench result that motivated re-opening DPDK.
