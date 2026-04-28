# Non-AWS Bare Metal Platforms for AnyScan Worker pps Scaling

**Status:** Research / planning, no implementation.
**Author:** anygpt-51 session
**Date:** 2026-04-28
**Pricing snapshot date:** 2026-04-28 (all $ figures captured this date; verify against vendor pages before procurement)

## Why this exists

Today's workers run on AWS `c6in.metal`. The ENA NIC family does not implement driver-mode AF_XDP zero-copy on Linux kernels ≤6.19.11 (the most recent kernel cap we have agentd validated against). With `XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY` unavailable on ENA, AF_XDP falls back to `XDP_COPY`, and on the 8-NIC `c6in.metal` topology this caps a single host at ~22M pps — about 2.66× our AF_PACKET baseline, not the ~30–50M pps projection we drew up when we first scoped AF_XDP. (Per memory `anyscan_afxdp_ena_constraint`.)

The question this doc answers: **can a non-AWS bare-metal host with Mellanox/mlx5 ConnectX NICs deliver driver-mode zerocopy and break the ENA ceiling, and what would that cost?**

The short answer is: yes on the kernel/NIC side, but the per-Mpps cost is dominated by acceptable-use-policy (AUP) risk, not by hardware $. The hosts with the right hardware mostly forbid the workload; the hosts that tolerate the workload mostly don't have the right hardware (or are too sketchy to put production scanners on). One provider — Latitude.sh — is the credible primary candidate, with Servers.com as backup.

## 1. Cost-per-Mpps comparison (headline)

Estimated per-host pps assumes mlx5 driver-mode zerocopy on a recent kernel (6.6+ stable). The mlx5 driver supports `NETDEV_XDP_ACT_XSK_ZEROCOPY` in mainline; `mlx5e_open_xsk()` / `mlx5e_init_xsk_rq()` in `drivers/net/ethernet/mellanox/mlx5/core/en/xsk/setup.c` register the XSK pool against the RQ. Throughput numbers below are conservative published-paper-class estimates for SYN-rate scanning workloads on ConnectX-5/6, not measurements from our agentd.

| Host | Monthly | NIC config | Est. zerocopy pps | $ per Mpps/mo | AUP for scanning |
|---|---|---|---|---|---|
| AWS `c6in.metal` (baseline) | ~$5,475 (1yr RI) | 8× ENA, no drv ZC | ~22M (copy mode) | ~$249 | Tolerated, with rate-limit & abuse contact |
| Equinix Metal `n3.xlarge.x86` | $3,285 ($4.50/hr × 730) | 4× 25G, Mellanox | ~50M | ~$66 | Permitted historically — **but service sunset 2026-06-30** |
| Equinix Metal `m3.large.x86` | $2,263 ($3.10/hr × 730) | 2× 25G bonded, Mellanox | ~30M | ~$75 | Same — **sunset 2026-06-30** |
| OVH HGR-HCI-1 | from ~$1,121 | 2× 25G + OLA up to 100G private (Mellanox on HGR tier) | ~50M | ~$22 | **Prohibited by ToS** — blocker |
| OVH Advance | from ~$98 | 1× 1–5G public (chip varies) | <5M | n/a | Prohibited |
| Hetzner AX102-U + dual-25G NIC | ~€110/mo + €12/mo NIC = ~$135 | 2× 25G add-on (vendor unspecified, likely Mellanox) | ~30M (theoretical) | ~$5 | **Prohibited by ToS, 6h response window** |
| Latitude.sh `rs4.metal.large` (Gen 4) | $1,471 | 2× 100G (Mellanox at this speed) | ~80–100M | ~$15–18 | Fair-Usage Policy is DDoS-focused, **no explicit port-scan ban** — needs written confirmation |
| Latitude.sh `m4.metal.large` (Gen 4) | $927 | 2× 10G (Mellanox) | ~25M | ~$37 | Same |
| Latitude.sh `m3.large.x86` (Gen 3) | $938 | 2× 10G (Mellanox) | ~25M | ~$37 | Same |
| Vultr Bare Metal | $300+ | 10G (chip not published) | ~10M | ~$30 | Standard AUP; scanning typically gated |
| Servers.com EBM | quote | Custom build, Mellanox available | configurable | TBD | Negotiable; Russian-origin operator with abuse-tolerance reputation in some cases |
| HorizonIQ (Equinix Metal migration partner) | quote | Mellanox builds available | TBD | TBD | Targeted as Equinix Metal sunset alternative |

**Methodology caveat:** the "$ per Mpps/mo" column is a procurement comparison shortcut, not a benchmark. Real per-Mpps will be measured once we have an instance under agentd. The dominant unknown is not pps; it is whether a provider will keep the instance powered on while it scans.

## 2. Per-provider summary

### 2.1 Equinix Metal — included for completeness, but sunsetting

Equinix announced 2024-11-07 that Equinix Metal is no longer sold and the platform will be **fully shut down 2026-06-30**. Existing customers can continue month-to-month until that date. This eliminates Metal as a long-term destination but does not strictly eliminate it as the venue for the experiment described in §3 — there is roughly two months of runway from this doc's date. We should not invest in Equinix-specific tooling that we'd have to throw away.

Hardware that would have been our first choice:
- **`m3.large.x86`** — AMD EPYC 7513 (32C), 256GB RAM, 2× 3.8TB NVMe, **2× 25G bonded Mellanox**, $3.10/hr (~$2,263/mo at 730h).
- **`n3.xlarge.x86`** — 32-core x86, 256GB RAM, **4× 25G Mellanox** (called out in CNCF CNF testbed network design), $4.50/hr (~$3,285/mo).
- **`c3.medium.x86`** — AMD EPYC 7401P (24C), 64GB, 2× 25G bonded Mellanox, $1.50/hr.

Kernel options: standard Linux distros via cloud-init / iPXE, no constraint on kernel version selection.

### 2.2 Hetzner Robot dedicated — strict no-scan AUP

The AX line (AMD-based, "matrix-ax") uses 1G default uplinks; multi-NIC and 10G/25G are sold as add-ons:

| Add-on | EU monthly | Speed | Vendor |
|---|---|---|---|
| 1G NIC | €2.20 | 1 Gbps | unspecified |
| 10G NIC | €5.00 | 10 Gbps | unspecified |
| 10G Intel NIC | €36.10 | 10 Gbps | **Intel** (only one explicitly named) |
| Dual 10/25G NIC | €12.00 | 10–25 Gbps | unspecified (likely Mellanox at 25G) |
| Dual 100G NIC | €39.00 | 100 Gbps | almost certainly Mellanox |

Theoretical procurement: AX102-U (16C Ryzen 9 7950X3D, 128GB DDR5) + dual-25G NIC ≈ €100/mo. **Most cost-effective box on paper in this entire study.**

But: Hetzner ToS prohibits port and network scanning. Their abuse team responds in ~6 hours, locks the IP, and there is a public history (ethereum/parity, sigp/lighthouse, multiple LowEndTalk threads) of even *unintentional* scan-shaped traffic getting boxes locked. Outbound RFC1918 ranges should be blocked at the host. **Not a viable destination for a scanner workload.**

### 2.3 OVH bare metal — strict no-scan AUP

OVHcloud's 2026 line is split into:
- **Advance 2026** — AMD EPYC 4005, 1–5 Gbps public, $98+/mo. Single NIC, no Mellanox at this tier.
- **Scale 2026** — 1–10 Gbps public, 6–25 Gbps private, $472+/mo.
- **High Grade (HGR)** — 1–10 Gbps public, **10–50 Gbps private with OLA (OVHcloud Link Aggregation)**, double PSU, hot-swap. $1,121+/mo. HGR-HCI-1 (compute-optimized) and HGR-SDS-1 (storage-optimized) both expose OLA-to-100Gbps private. Mellanox NICs at 25G/100G are standard at this tier.

Same AUP problem. OVH's Service-Specific Terms explicitly call out "intrusion attempts (including port scans, sniffing, spoofing)." Documented behavior: abuse report → server reboots into rescue mode, customer notified. Not a viable destination.

### 2.4 Latitude.sh — primary candidate

Gen 4 line (DDR5, AMD Genoa/Bergamo, **up to 200 Gbps networking**) — the only commodity-priced bare metal in this study with explicit dual-100G:

| Plan | Hourly | Monthly | CPU | Network |
|---|---|---|---|---|
| `rs4.metal.xlarge` | $3.40 | $2,482 | AMD 9554P 64C | 2× 100G |
| `m4.metal.xlarge` | $2.98 | $2,172 | AMD 9455P 48C | 2× 10G |
| `f4.metal.large` | $2.05 | $1,497 | AMD 9275F 24C @4.1 | 2× 100G |
| **`rs4.metal.large`** | **$2.02** | **$1,471** | AMD 9354P 32C | **2× 100G** |
| `m4.metal.large` | $1.27 | $927 | AMD 9254 24C | 2× 10G |

Gen 3 (DDR4, AMD Milan):

| Plan | Hourly | Monthly | CPU | Network |
|---|---|---|---|---|
| `m3.large.x86` | $1.28 | $938 | AMD 7543P 32C | 2× 10G |
| `s3.large.x86` | $0.89 | $650 | AMD 7443P 24C | 1× 10G |
| `c3.large.x86` | $0.68 | $496 | AMD 7443P 24C | 2× 10G |
| `c3.small.x86` | $0.26 | $190 | Intel E-2386G 6C | 1× 10G |

NIC vendor not stated on the public page. At 100G the only realistic options in commodity bare metal are Mellanox ConnectX-6/Dx and Broadcom Thor; given Latitude.sh's positioning as the "Equinix Metal sunset alternative" (they have a published migration blog) and that Equinix Metal n3.xlarge.x86 was Mellanox, the working assumption is Mellanox at 100G. **Confirm before commit.**

Bandwidth allowance: 20 TB outbound free per instance, infinite inbound. Overage rate not published — must obtain in writing.

Provisioning: 5-second deploys for stock images (Ubuntu, Debian, Rocky, RHEL, Windows); custom images via iPXE in 10–30 min. cloud-init user-data works on the 5s deploy path.

AUP: the published Fair Usage Policy is centered on DDoS scrubbing and null-routing thresholds (default 2-hour null-route on detection). I could not find an explicit prohibition on port scanning or network reconnaissance in the FUP excerpt. Latitude.sh is also positioning explicitly for migrating Equinix Metal customers, some of whom run scanner workloads. **This does not equal "scanning is allowed"** — it equals "we should ask before committing $1,500/mo and get an answer in writing." Treat this as a precondition, not an assumption.

### 2.5 Comparison provider — Servers.com (EBM)

Servers.com offers two products:
- **Scalable Bare Metal (SBM)** — hourly billing, public outbound metered per GB.
- **Enterprise Bare Metal (EBM)** — custom config, monthly billing, sales-quoted.

EBM supports custom NIC builds including Mellanox 25G/100G. Pricing is not on the public site; obtaining a configured quote (similar profile to Latitude.sh `rs4.metal.large`) is part of the §3 plan. Servers.com has historically operated a more permissive abuse stance than the Western European hyperscalers, but their AUP is not publicly published in detail and must be obtained.

### 2.6 Other candidates worth a follow-up call (not deep-researched)

- **HorizonIQ** — explicitly markets to Equinix Metal refugees, custom builds with Mellanox available, US-centric.
- **OpenMetal** — published bare-metal pricing catalog, Ceph/OpenStack focus, Mellanox common.
- **Cherry Servers, ServerMania, FDCservers** — name-checked in the broader bare-metal pricing literature; need direct outreach.
- **DediDuck / ClientVPS / "scanner-friendly"** — explicitly market to scanning use-cases, but the operator quality is significantly lower; **not recommended for production AnyScan**.

## 3. Recommended path: a single ~$1,500/mo experiment on Latitude.sh

### 3.1 Hypothesis

A single Latitude.sh `rs4.metal.large` (AMD 9354P, 32C, 2× 100G, $1,471/mo) on a 6.6+ stable kernel with `mlx5_core` and `XDP_ZEROCOPY | XDP_FLAGS_DRV_MODE` will sustain at least **2× the AF_XDP-on-ENA pps** (≥45M pps) on a SYN-only port-scan profile, against a pre-arranged target rack we control. If true, $/Mpps on Latitude.sh is ~$15–18 vs ~$249 on c6in.metal.

### 3.2 Preconditions (gate the spend)

1. **Latitude.sh AUP confirmation in writing.** Email their abuse team with a one-paragraph description of the workload (rate-limited authorized scanning, no exploitation traffic, abuse contact provisioned, source IPs reverse-DNS to anyscan.example) and get a yes-or-no. **No commit until this returns yes.**
2. **NIC vendor confirmation in writing.** Ask sales whether `rs4.metal.large` is Mellanox ConnectX-6 Dx (or similar) at 100G. Worst case is Broadcom; the rest of the plan is Mellanox-conditional.
3. **Egress overage rate.** 20 TB free is fine for the experiment but the production unit-economics need a per-GB number.

### 3.3 Provisioning (~1 day from precondition green light)

1. Deploy stock Ubuntu 24.04 (HWE) image — gets us a 6.8 kernel with mature mlx5 zerocopy. 5-second deploy.
2. cloud-init bootstraps agentd, tc/qdisc egress reservation (per the existing `e97012f` work in this repo), and the inventory-policy fetcher (per `ef60f6f`).
3. Bring up an `xdp-bench --zc` smoke test against a loopback target to confirm zerocopy is engaged (`bpftool net show` should report `xdp/zc` on the iface; `xsk_pool` ring should be allocated against the actual RQ).

### 3.4 Experiment

1. Run the same SYN-rate test plan we run today on `c6in.metal` — same plugin set, same target rack, same target ports.
2. Capture pps at the NIC (`ethtool -S`) and from agentd's emitted metrics.
3. Compare to the c6in.metal baseline. The success criterion is the §3.1 hypothesis.

### 3.5 Cost ceiling

- One `rs4.metal.large`: **$1,471/mo** ($2.02/hr — first month is roughly $1,500 for 30 days, and we should be able to draw a conclusion in <14 days, so committed spend is closer to $700.)
- Egress within 20 TB free allowance — should not be the binding cost.
- **Hard ceiling for the experiment: $2,000.** If we are still paying past two billing cycles without a production decision, escalate.

### 3.6 Provisioning time estimate

- AUP/sales confirmation: 2–5 business days (sales response is the long pole).
- Server live: same day after confirmation (Latitude.sh 5-second deploy + cloud-init).
- Smoke + first comparable run: 1–2 days post-deploy.
- **End-to-end: ~1 week from "go" to first publishable number.**

## 4. Risks and unknowns

### 4.1 Latitude.sh AUP could come back as "no"

Most likely failure mode of the plan. Backup provider in priority order:
1. **Servers.com EBM** — needs a quote and an AUP conversation. Slower (their EBM lead time is days-to-weeks for custom builds).
2. **HorizonIQ** — explicit Equinix Metal migration target market.
3. **Co-location at a neutral DC + own hardware** — slow (weeks to months) but the only option that puts AUP entirely under our control. Out of scope for "$2k experiment" but is the right answer if we ever scale to a fleet.

### 4.2 NIC vendor could be Broadcom, not Mellanox

If `rs4.metal.large` ships with Broadcom Thor instead of Mellanox CX-6, the plan still partly works — Broadcom's `bnxt_en` driver does have AF_XDP zerocopy support, but it has historically lagged mlx5 in maturity and the per-queue throughput numbers are lower. Falling back to a Mellanox-confirmed Latitude.sh SKU (the older Gen 3 `m3.large.x86` is plausible — same name as the Equinix Metal SKU and likely same hardware lineage) loses the 100G uplink.

### 4.3 We may underestimate the AnyScan-side work

Right now agentd does AF_XDP detection per the existing perf branches (`perf/portscan-pps`, `perf/dynamic-pps-rate`, `perf/portscan-dpdk`, `feat/path-scan-fast-path` are visible on origin). Driver-mode zerocopy on a 100G mlx5 path may surface bugs in the userspace plugin pipeline that AF_PACKET on ENA never exercised: per-RQ NUMA pinning, larger XSK ring sizing, jumbo-frame handling at 9000 MTU. None of this is hard, but it is not free.

### 4.4 Public IPv4 inventory and IPv6 story

- Latitude.sh: 1× IPv4 / 1× IPv6 by default per server; additional IPs available on request.
- Equinix Metal: Public IPv4 management is a known friction point — the inventory model from `anyscan_inventory_constraints` (raw-IP-only, 80/443-only) interacts with how the provider issues addresses. Worth re-reading that memory before any provider commit.
- Hetzner / OVH: classic /29 and /27 allocations available, but irrelevant given the AUP situation.

### 4.5 Equinix Metal sunset is ~14 months out

If we read this paragraph in March 2026 and we have not finished the experiment, Equinix Metal is no longer in the option set at all. There is no scenario where we commit to Equinix Metal as the answer.

### 4.6 Findings that did not survive the AUP filter

This study originally scoped a head-to-head OVH HGR vs Hetzner AX-with-25G-NIC comparison. Both have superior $/Mpps to anything else listed here on hardware grounds (Hetzner especially — AX102-U + dual-25G NIC at ~€135/mo would have been the obvious winner). Both are eliminated by ToS, not by hardware. **Unless we are prepared to engage these providers under a different contract (master agreement with explicit scanning carve-out), they should not be treated as candidates regardless of price.**

## 5. Mlx5 zerocopy verification

Direct check against the kernel source (`drivers/net/ethernet/mellanox/mlx5/core/en/xsk/setup.c`, master branch as of 2026-04-28):

- `mlx5e_open_xsk()` — opens XSK resources, registers the `xsk_pool` against the RQ.
- `mlx5e_init_xsk_rq()` — `rq->xsk_pool = pool` assignment confirms zerocopy path wires through the actual receive queue, not a copy intermediary.
- `mlx5e_validate_xsk_param()` — enforces XSK constraints (frames ≤ PAGE_SIZE, chunk_size ≤ 65535).
- File includes `<net/xdp_sock_drv.h>` — the driver-mode XDP socket header.

Conclusion: **mlx5 driver-mode zerocopy is supported and has been since approximately kernel 5.5**. Stable kernels we'd realistically run (Ubuntu 24.04 HWE 6.8, Rocky 9 / RHEL 9 with ELRepo 6.x, Debian 12 backports kernel) all have this path. Userspace can request it via `XDP_ZEROCOPY` in the bind flags.

## 6. Open follow-ups (in order)

1. Email Latitude.sh abuse + sales: confirm AUP for authorized scanning, confirm NIC vendor for `rs4.metal.large`, get egress overage rate. **(Owner: TBD)**
2. Same set of questions to Servers.com for an EBM quote matching `rs4.metal.large` profile. **(Owner: TBD)**
3. If Latitude.sh confirms, deploy one box and run §3.4. **(Owner: TBD)**
4. If both Latitude.sh and Servers.com decline, re-scope to "co-locate own hardware in a neutral DC." That is a separate planning doc.

## Sources

Pricing and policy data was captured 2026-04-28 from:

- [Equinix Metal sunset announcement (DataCenterDynamics)](https://www.datacenterdynamics.com/en/news/equinix-to-kill-off-metal-by-june-2026/)
- [Equinix Metal sunset migration guide (Latitude.sh blog)](https://www.latitude.sh/blog/equinix-metal-sunset-how-to-reduce-the-migration-burden)
- [Equinix Metal m3-large product page](https://metal.equinix.com/product/servers/m3-large/)
- [Hetzner AX line matrix](https://www.hetzner.com/dedicated-rootserver/matrix-ax/)
- [Hetzner add-on price list](https://docs.hetzner.com/robot/dedicated-server/dedicated-server-hardware/price-server-addons/)
- [Hetzner abuse / netscan tutorial](https://community.hetzner.com/tutorials/solving-potential-netscan-on-windows/)
- [Hetzner block-private-traffic tutorial](https://community.hetzner.com/tutorials/block-outgoing-traffic-to-private-networks/)
- [OVHcloud bare metal landing](https://us.ovhcloud.com/bare-metal/)
- [OVHcloud Service-Specific Terms](https://us.ovhcloud.com/legal/service-specific-terms/)
- [OVHcloud Bare Metal 2026 launch announcement](https://corporate.ovhcloud.com/en/newsroom/news/ovhcloud-bare-metal-2026-amd/)
- [OVHcloud HGR-HCI-1](https://us.ovhcloud.com/bare-metal/high-grade/hgr-hci-1/)
- [OVHcloud HGR-SDS-1](https://us.ovhcloud.com/bare-metal/high-grade/hgr-sds-1/)
- [Latitude.sh pricing](https://www.latitude.sh/pricing)
- [Latitude.sh Fair Usage Policy](https://www.latitude.sh/legal/fair-usage)
- [Latitude.sh custom images / iPXE docs](https://www.latitude.sh/docs/servers/custom-images)
- [Latitude.sh 5-second deploys + user-data changelog](https://www.latitude.sh/changelog/user-data-available-on-5-second-deployments)
- [Vultr Bare Metal product page](https://www.vultr.com/products/bare-metal/)
- [Servers.com Enterprise Bare Metal](https://www.servers.com/products/dedicated-servers)
- [Servers.com Scalable Bare Metal](https://www.servers.com/products/scalable-bare-metal)
- [HorizonIQ Equinix Metal alternative blog](https://www.horizoniq.com/blog/equinix-metal-alternative/)
- [AF_XDP kernel docs](https://docs.kernel.org/networking/af_xdp.html)
- [mlx5 XSK setup source (torvalds/linux master)](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/mellanox/mlx5/core/en/xsk/setup.c)
