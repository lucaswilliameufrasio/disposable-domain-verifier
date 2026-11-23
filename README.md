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

# Blocklist maintenance

Run `./scripts/update_blocklist.sh` from a checkout with Python 3 and network
access. It downloads both mandatory sources, validates all entries and the
protected domains, merges `assets/confirmed-disposable-domains.txt`, sorts and
deduplicates, and replaces `assets/blocklist.txt` only after validation. Add
confirmed local inclusions to that file rather than editing the generated list.
Reviewed exact-match false positives in `assets/blocklist-exclusions.txt` are
removed from the candidate and logged. An inclusion/exclusion conflict fails
the update; entries in `assets/legitimate-domains.txt` still make it fail.
Never use `domains_strict.txt`: it includes legitimate providers and aliases.

The updater logs UTC time, source URLs, SHA-256 hashes, byte and domain counts,
incremental union sizes, and added/removed totals. Keep the workflow run logs
for auditing. It rejects either failed download, invalid data, missing known
domains, protected domains, source counts outside 9,000–20,000 and
3,500–10,000 respectively, and additions or removals over the larger of
1,000 domains or 10% of the current list. Investigate abnormal changes rather
than bypassing these checks. Bounds were based on the 2026-11-16 snapshot and
need review as sources evolve; they do not prove individual entries are safe.

Sources investigated on 2026-11-16:

* [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)
  is CC0 and its plain `.conf` contained 10,274 domains (SHA-256
  `f94b3951bf486901172393608554a72c3fc06fbff2a5f233536bf4721996b114`).
* [7c/fakefilter](https://github.com/7c/fakefilter) is BSD-3-Clause and
  describes daily updates from active provider monitoring. Its grouped text
  file is normalized by ignoring `#` headings. At commit
  [`f2467813d0e5f6099412a36658f72a235533c51d`](https://github.com/7c/fakefilter/commit/f2467813d0e5f6099412a36658f72a235533c51d)
  (2026-11-16) it contained 4,790 unique domains, 1,589 overlapping the
  community baseline, and all ten locally retained domains. Its SHA-256 was
  `9c64fbb45ed1a92499a9fafa38005e55c823e3f66e83193d9777d992a32c294b`.
  The copyright, conditions and disclaimer are reproduced in
  `assets/fakefilter-license.txt`, which is included in the application image.
* [disposable](https://github.com/disposable/disposable-email-domains) is a
  daily MIT-licensed aggregator, but its repository license alone does not
  establish the license of all constituent datasets. Its normal list at commit
  [`e417abad79a74e3685f0359e6a7ac2f1ae8aa25c`](https://github.com/disposable/disposable-email-domains/commit/e417abad79a74e3685f0359e6a7ac2f1ae8aa25c)
  had 108,547 entries (SHA-256
  `5c2bc87fa47998167b22713ea1ac2528e05353211742300a04279e8a70632f1e`).
  It is **not** used as an input.
* [mehrtat](https://github.com/mehrtat/disposable-email-domain) is an MIT
  daily aggregator of multiple independently licensed lists, including the
  two above. Its 193,177 entries included all entries in both sources. It
  tolerates partial upstream failures and introduces 84,630 additional entries;
  it is not included without further quality and license review. Its snapshot
  SHA-256 was `f638ee61447bd035808f903cf418e38845f6a4effbd31dcdab38ce3e72eef790`.

The `disposable` commit's [source map](https://raw.githubusercontent.com/disposable/disposable-email-domains/e417abad79a74e3685f0359e6a7ac2f1ae8aa25c/domains_source_map.txt)
(SHA-256 `fdfa71fab86bf4e650272add416bb31a80378fed480e61a84a3548f7ed9dbe13`)
associated the previous 108,581-domain candidate with 44 sources. It mapped
108,318 entries and left 263 unmapped; 54,313 had `throwaway.cloud` among
their sources, and 27,952 had it as their only mapped source. The site says
its data is free to use, but its GitHub repository did not identify a license.
The map is upstream attribution, not independent proof of provenance. To avoid
depending on that unresolved dataset or automatically importing its other
sources, the candidate uses the community list and FakeFilter directly.

The revised initial union is 13,463 domains, 3,189 additions and no removals
versus the previous checked-in list, SHA-256
`173acb8aaf0997438e93dd69a049376f44cec8fa0e182d2d6abd548009c7396b`.
This one-time migration exceeds normal variation limits; normal runs cannot
accept a change of that size.
The scheduled workflow on protected `main` tests and proposes updates. The
blocklist App merges its own PR only when it changes `assets/blocklist.txt`
alone and the exact candidate commit passes CI, `blocklist-safety`, and
Cururu. It rechecks the author, branches, candidate blob, and base revision
immediately before requesting a normal merge with the reviewed head SHA.
If a gate or pre-merge verification fails, the PR is left open. GitHub's
merge API enforces the head SHA but has no equivalent base SHA precondition,
so the workflow additionally requires a **separate** strict `main` ruleset
with `check` and `blocklist-safety` from GitHub Actions. The App must not be
able to bypass this ruleset. If GitHub rejects the merge or the policy cannot
be verified, the workflow stops. It also verifies the resulting merge parents
and alerts on any mismatch without automatically reverting the merge.

Keep the existing PR-only exception in the approval ruleset for the blocklist
App, not in the strict checks ruleset. This does not change human approval for
other PRs or rely on GitHub's native auto-merge setting.

On 2026-11-16 the 3,201 initial additions were checked against the
[Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)
(SHA-256 `fc62f83e482dd86d3c50216fcbf5bb6c3b18f13d0ffdfc462b14e36b8a97bfba`),
the community [additional suffixes](https://github.com/disposable-email-domains/disposable-email-domains/blob/main/publicsuffixlist.local),
the `disposable` [allowlist](https://github.com/disposable/disposable/blob/master/whitelist.txt)
(SHA-256 `03c5c95e7079c4e138c3297f2bf0fd609ad9d97f265dc89e2539070bb575672b`),
its [mail-service catalog](https://github.com/disposable/static-disposable-lists/blob/master/mailservices.json)
(SHA-256 `ebdaed7bd055b6146a12aab4d879467c6042115e3a50573afd6ff5194f375bb4`)
and a Tranco top-million snapshot (SHA-256
`b505de59e3cb5b5f0c79a42bb3e156fb055f1ddec5c00fdb673ecf24c79a20e8`).
Twelve entries were excluded: eight shared registration/dynamic-DNS suffixes,
the Spamgourmet forwarding service, and three domains with disputed
false-positive reports. Tranco popularity alone is not evidence a domain is
legitimate: disposable providers also appear there. Of the 3,189 remaining
additions, 3,185 appeared in the upstream source map, with at least two listed
sources for 1,431; those sources can share data and are not necessarily
independent. These checks do not establish the status of every domain or
guarantee that ownership will not change.

Updating or merging the file alone does **not** update a running instance. The
service loads the file at startup, and the deploy image contains the list from
its build checkout. A newly built image must be deployed and its process started
before the deployed instance uses that version.

# Branch coverage

The target is at least 80% of measurable branches. Do not exclude validation,
error handling, or domain logic to reach it. Branch coverage for Rust currently
requires nightly's unstable instrumentation; normal builds and tests use the
project's pinned stable toolchain. With `cargo-llvm-cov` and a nightly toolchain
installed, run:

```bash
mkdir -p target/coverage
cargo +nightly llvm-cov --branch --json --output-path target/coverage/rust-branches.json
python3 -c 'import json; t=json.load(open("target/coverage/rust-branches.json"))["data"][0]["totals"]["branches"]; print("Rust branches: {}/{}".format(t["covered"], t["count"])); assert t["count"] and t["covered"]/t["count"] >= 0.8'
```

For the Python updater, `uvx` can run coverage.py without installing it into
the project or changing the global Python installation:

```bash
mkdir -p target/coverage
COVERAGE_FILE=target/coverage/blocklist-coverage PYTHONDONTWRITEBYTECODE=1 uvx --from coverage==7.17.3 coverage run --branch --include='*/scripts/update_blocklist.py' -m unittest discover -s scripts -p 'test_*.py'
COVERAGE_FILE=target/coverage/blocklist-coverage uvx --from coverage==7.17.3 coverage json -o target/coverage/python-branches.json
python3 -c 'import json; t=json.load(open("target/coverage/python-branches.json"))["totals"]; print("Python branches: {}/{}".format(t["covered_branches"], t["num_branches"])); assert t["num_branches"] and t["covered_branches"]/t["num_branches"] >= 0.8'
```

These are separate reports: neither measures the other language. Document and
justify any future coverage exclusions; no source files are excluded from the
Rust report, and the Python report covers the production updater.

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
