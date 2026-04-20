# AnyScan OpenWrt Package Skeleton

This directory contains a native OpenWrt/GL.iNet package layout for a minimal
Opal-oriented AnyScan worker deployment.

## Package split

- `anyscan-agent-core`
  - installs the Rust worker binary
  - installs `/etc/init.d/agentd`
  - installs the UCI config at `/etc/config/agentd`
  - installs the runtime wrapper at `/usr/libexec/agentd/agentd-run.sh`
  - installs bundled detector assets under `/usr/share/agentd/extensions/bundled`
- `anyscan-agent-helpers`
  - installs the bootstrap provisioner manifest/script
  - requires Python 3 on the router
- `anyscan-agent-scanner`
  - installs the port-scan adapter manifest/script
  - installs the target-specific scanner binary
- `anyscan-agent-opal-full`
  - meta package for `core + helpers + scanner + tor`

## Expected runtime layout

- binary: `/usr/sbin/agentd`
- config: `/etc/config/agentd`
- init: `/etc/init.d/agentd`
- helper assets: `/usr/share/agentd/extensions/...`
- scanner binary: `/usr/libexec/agentd/scanner`
- state token file: `/var/lib/agentd/agent.env`
- artifacts: `/var/lib/agentd/artifacts`

The service runs through `procd` as root, which is the simplest fit for a
small OpenWrt device and avoids Linux host bundle assumptions like `systemd`
and dedicated service users.

## Preparing staged assets

Before copying this package into the GL.iNet/OpenWrt SDK, stage the target
binaries and helper assets:

```bash
./apps/anyscan/openwrt/prepare-opal-package.sh \
  --agent-bin /path/to/target/anyscan-worker \
  --scanner-bin /path/to/target/scanner
```

This populates:

- `apps/anyscan/openwrt/package/anyscan-agent/staging/root/usr/sbin/agentd`
- `apps/anyscan/openwrt/package/anyscan-agent/staging/root/usr/libexec/agentd/scanner`
- `apps/anyscan/openwrt/package/anyscan-agent/staging/root/usr/share/agentd/extensions/...`

## Building inside the SDK

Copy `apps/anyscan/openwrt/package/anyscan-agent` into your SDK under
`package/anyscan-agent`, then build:

```bash
make package/anyscan-agent/compile V=s
```

Install the resulting `ipk` packages with `opkg`.

## Publishing stable downloads

After building inside the SDK, copy the produced `ipk` files into a flat
publish directory with stable names. By default, the publish helper writes to
`/var/lib/anyscan/openwrt-opal`, which can be served by the AnyScan API.

```bash
./apps/anyscan/openwrt/publish-opal-packages.sh \
  --source-dir /path/to/sdk/bin/packages/...
```

This emits:

- `anyscan-agent-core.ipk`
- `anyscan-agent-helpers.ipk`
- `anyscan-agent-scanner.ipk`
- `anyscan-agent-opal-full.ipk`
- `install-opal-agent.sh`
- `SHA256SUMS`

## Router-side auto install

Once those files are published on the AnyScan host, the router can install
everything in one step directly from the website:

```sh
wget -O - https://scan.anyvm.tech/api/openwrt/opal/install.sh | sh -s -- \
  --bootstrap-code YOUR_BOOTSTRAP_CODE \
  --profile full
```

If you want to host the same files elsewhere, the generic form is:

```sh
wget -O - https://host.example/anyscan-opal/install-opal-agent.sh | sh -s -- \
  --base-url https://host.example/anyscan-opal \
  --bootstrap-code YOUR_BOOTSTRAP_CODE \
  --profile full
```

The installer will:

- update `opkg`
- install feed dependencies (`tor`, `python3-light`, etc.) as needed
- download the selected `ipk`s and verify them against `SHA256SUMS`
- configure `/etc/config/agentd`
- enable/start `tor` when needed
- enable/start `agentd`

## Default router config assumptions

- control URL defaults to the current onion endpoint
- control proxy defaults to `socks5h://127.0.0.1:9050`
- the init wrapper will wait for the Tor SOCKS port when possible
- `enabled` defaults to `0` until you provide a bootstrap code and enable the service
