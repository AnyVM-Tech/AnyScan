# Port-Scan DPDK Scope Memo

_Date: 2026-04-27_
_Branch: `perf/portscan-dpdk` (apps/anyscan)_
_Tracker: anygpt-32 (parallel: anygpt-31 multi-NIC + AF_XDP on `perf/portscan-multi-nic-afxdp`)_

## Objective

Assess feasibility of adding **DPDK userspace networking** to the AnyScans port scanner so that c6in.metal (and similar ENA-class hosts) can approach the single-NIC ~14 M pps theoretical ceiling instead of the ~1.7–3 M pps AF_PACKET ceiling measured in PR #13/#28 bench (anygpt-24 reference).

This is a **Phase 1 scope-discovery deliverable**, read-only. No build-system or scanner code has been changed.

## Findings

### Where the scanner binary comes from

`apps/anyscan/package-worker-bundle.sh:519-525` resolves the scanner from one of:
- `$ANYSCAN_PACKAGE_VULNSCANNER_BIN` (operator override)
- `../../VulnScanner-zmap-alternative-/scanner` (build-from-source default — sibling to AnyGPT clone)
- `/opt/anyscan/bin/scanner` (already-installed fallback)

The first match resolves to `https://github.com/Lorikazzzz/VulnScanner-zmap-alternative-` — an **external repo not under AnyVM-Tech control**. The bundle pipeline copies the prebuilt `scanner` ELF; it does not build the scanner itself.

### What the scanner is

| Aspect | Value |
| --- | --- |
| Language | C (gnu99) |
| Size | 3,643 LOC (15 .c + 7 .h files) |
| Heritage | Hybrid — masscan internals (`crypto-blackrock`/`crypto-blackrock2` randomized address generator) + zmap-style sender/receiver split |
| Build | `Makefile`, `gcc -O3 -pthread`, `make install` to `/usr/bin/scanner` |
| Default datapath | `AF_PACKET` raw socket (`src/sender.c`, `src/send-pfring.c` flush_tx_ring uses TX ring) |
| Existing kernel-bypass | **PF_RING ZC** behind `USE_PFRING_ZC=1` Make flag — `src/send-pfring.c` (104 LOC), `src/recv-pfring.c` (34 LOC), gated by `#ifdef USE_PFRING_ZC` |
| DPDK code today | **None**. `grep -ln 'dpdk\|DPDK\|rte_'` over the entire scanner src/include returns zero hits |
| Upstream maintenance | "Add files via upload" commits, no branches, last update Apr 9 — solo-maintainer hobby project, not a vendor we can expect to land DPDK PRs |

### A/B/C classification

The Phase 1 brief defined three categories:

> A. zmap fork: enable upstream `--enable-dpdk` flag (medium effort, 1–2 days)
> B. custom Rust: rust-dpdk/capsule integration, weeks of work — STOP and surface
> C. masscan-derived: built-in custom userspace driver path that performs similarly to DPDK, no DPDK link, just config

**None of A/B/C is a clean fit, but the closest is a hybrid of B and C:**

- **Not A** — this is not zmap. There is no upstream `--enable-dpdk` flag and no netscan branch to merge.
- **Not C as written** — the brief assumes "masscan-derived" means a built-in PMD that already performs at DPDK class. That description matches **masscan proper** (which has a custom PF_RING/`--pfring` userspace driver path). This scanner is *masscan-derived* in the sense that it lifted the address-shuffle and probe-template code, but the *datapath* is plain AF_PACKET. The kernel-bypass option present (PF_RING ZC) is **commercial, license-keyed, and has no documented ENA support**, so it does not give us c6in.metal performance for free.
- **Effort matches B** — adding DPDK requires weeks of new C code on a third-party repo. See effort breakdown below.

### Effort to add DPDK to this scanner

Following the existing `USE_PFRING_ZC` pattern in `Makefile` and `src/send-pfring.c` / `src/recv-pfring.c`, a minimum viable DPDK integration looks like:

| Component | Estimate |
| --- | --- |
| `src/send-dpdk.c` — EAL init, mempool/mbuf alloc, `rte_eth_tx_burst` polling loop, lcore pinning | ~250–400 LOC |
| `src/recv-dpdk.c` — `rte_eth_rx_burst` consumer, decode into existing receiver pipeline | ~150–250 LOC |
| `include/scanner.h` additions — DPDK port id / queue id / mempool handles in `thread_context_t` | ~40 LOC |
| `Makefile` — `USE_DPDK=1` target, `pkg-config --libs libdpdk`, link `rte_eal rte_mbuf rte_ethdev rte_net rte_net_ena` | small |
| CLI flags in `src/parsing.c` — `--dpdk`, `--dpdk-port`, `--dpdk-eal-args` | ~50 LOC |
| EAL bring-up sequencing in `src/main.c` / `src/engine.c` — has to happen before threading and before the existing AF_PACKET socket open path | ~100 LOC |
| Address resolution / ARP — DPDK has no kernel ARP table, so MAC-of-gateway has to be supplied or resolved out-of-band | non-trivial |

Net: **~600–900 LOC of new C**, plus build-system and host-bring-up work (hugepages, vfio-pci binding). On a third-party repo we don't own. Realistic calendar: **2–3 weeks of focused work**, not 1–2 days.

This is **scope-equivalent to category B** even though the language is C, not Rust.

### What the AnyGPT side would need (in scope of this PR if we proceed)

Even if upstream support landed tomorrow, this PR's *AnyGPT-side* changes would still be substantial — and these are the only parts I can author without modifying the external scanner repo:

- `package-worker-bundle.sh` — new `scanner-dpdk` build target, run with `USE_DPDK=1` in addition to the stock binary
- `tools/setup-dpdk.sh` (new, idempotent + reversible) — allocate hugepages (1 GB or 2 MB pages), load `vfio-pci`, bind specified ENIs, leaving eth0 on kernel networking for control-plane heartbeat
- `runtime.worker.env.template` — new env knobs:
  - `ANYSCAN_SCANNER_DPDK_ENABLED`
  - `ANYSCAN_SCANNER_DPDK_INTERFACES` (comma-separated PCI BDFs or kernel iface names pre-bind)
  - `ANYSCAN_SCANNER_DPDK_HUGEPAGES_GB`
  - Skip rule: only enable when `>=2` ENIs are present, so eth0 stays on kernel
- `install-worker-bundle.sh` — top-level: **out of scope per anygpt-31's territory**, so changes route via `apply_host_resource_defaults`-style hooks elsewhere or the env file
- `src/bin/anyscan-worker.rs` port-scan dispatch — **out of scope per task brief**

But again — none of this matters until the scanner binary itself can speak DPDK, which it cannot today.

## Coordination with anygpt-31

anygpt-31 is doing multi-NIC + AF_XDP on `perf/portscan-multi-nic-afxdp`. Their work touches the orchestration files this brief tells me to stay out of (`vulnscanner-zmap-adapter.py`, `install-worker-bundle.sh`, `src/bin/anyscan-worker.rs` port-scan dispatch). No file conflict expected with a future DPDK PR — DPDK's natural surface is `package-worker-bundle.sh` build target + `tools/setup-dpdk.sh` + `runtime.worker.env.template`.

**However:** AF_XDP and DPDK are mutually exclusive on the same NIC. If anygpt-31's path proves sufficient for c6in.metal aggregate throughput across 8 ENIs, DPDK becomes a marginal-gain effort rather than a needed one. Worth re-evaluating the value proposition once anygpt-31 lands.

## Recommendation

**STOP, per the Phase 1 brief.**

Three viable paths forward, ordered by my preference:

1. **Wait on anygpt-31.** AF_XDP is also kernel-bypass-class and is supported by the Linux kernel ENA driver natively (ENA driver advertises XDP hooks). If anygpt-31 lands AF_XDP × 8 ENIs and clears the throughput target, no DPDK work needed. Defer this branch and revisit if anygpt-31's bench shows a gap.
2. **Fork the scanner under AnyVM-Tech and add DPDK there.** ~2–3 weeks of focused C work on a fork of `Lorikazzzz/VulnScanner-zmap-alternative-`. Pinning `package-worker-bundle.sh` at our fork is straightforward. This is the "really do DPDK" path; commit to a multi-week project.
3. **Replace the scanner with a DPDK-native one.** masscan with `--pfring` already exists; for a true DPDK datapath, options are zmap's never-merged `netscan` branch, `ZMap2`, or building a new one. Even larger scope.

Option 1 is what I recommend the orchestrator pick. Options 2 and 3 are both "new project" tier and should be planned separately, not stuffed into a single PR.

## What I'm doing now

- Branch `perf/portscan-dpdk` exists locally with this memo only. Nothing committed yet.
- Reporting `needs-input` to the orchestrator with this memo as the artifact.
- Not creating a PR — there's no implementation to land. If the orchestrator picks option 2/3, we need a multi-week plan, not this branch.
- Branch can be deleted by the orchestrator at any time without loss.

## References

- Bench data: anygpt-24 (PR #13/#28 lineage, AF_PACKET ~1.7 M pps on c6in.xlarge with `sender_threads=4 receivers=1`)
- Existing PF_RING hook: `Lorikazzzz/VulnScanner-zmap-alternative-` `Makefile`, `src/send-pfring.c`, `src/recv-pfring.c`
- AWS ENA DPDK PMD: `rte_net_ena` (mainline DPDK, requires `vfio-pci` + hugepages, consumes the ENI exclusively)
- Parallel work: anygpt-31 on `perf/portscan-multi-nic-afxdp` — multi-NIC AF_PACKET / AF_XDP
