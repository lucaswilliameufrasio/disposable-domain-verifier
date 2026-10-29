# Disposable Domain Verifier

# Installation

1. Clone the repository:

``` bash
git clone https://github.com/lucaswilliameufrasio/disposable-domain-verifier.git
cd domain verifier
```

2. Build and run:

``` bash
cargo run --release
```

3. The server listens on port 9999 by default.

# Deploy to a VPS

With Cargo locally and a rootless Docker daemon on the VPS, run `make deploy`. The
interactive Rust CLI asks for an SSH alias from `~/.ssh/config`, host port, and
remote IPv4 bind address; it has no default host. It builds the Rust production
image for the VPS CPU and streams it over SSH. The bind defaults to loopback;
to reach it from a reverse proxy on another host, enter the VPS's private or
Tailscale IPv4 address and allow only the proxy through the firewall. Configure
the proxy to forward to the selected address and port, then verify
`/health-check` before directing traffic there. The script does not change DNS
or reverse-proxy configuration. Replacing an existing container requires
confirmation.

Prerequisites: Cargo, a working SSH alias, and rootless Docker on the VPS. A
local Docker daemon is not required. If
the build machine is not Linux on the same CPU architecture as the VPS, install
Zig and `cargo-zigbuild`; the script uses `cargo zigbuild` for that cross-build.
The image itself is built by the destination host's native Docker daemon, with
no Docker Buildx or QEMU. The blocklist bundled into the image is what the
service uses at startup.

# Usage

Verify a domain:

```bash
curl 'http://localhost:9999/v1/domains/verify?domain=mailinator.com'
```

Sample response:

```json
{
  "domain": "mailinator.com",
  "is_disposable": true,
  "reason": "Listed as disposable",
  "source": "blocklist.txt",
  "checked_at": "2025-05-12T09:21:32.796957+00:00"
}
```
