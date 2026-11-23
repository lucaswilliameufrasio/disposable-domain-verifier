# Rust blocklist updater: experimental migration

This is a draft, not a cutover. The scheduled workflow continues to use the
Python updater and its tests. Do not remove or disable it until the Rust
candidate has complete behavioral coverage and the full workflow is measured.

The candidate is isolated behind the `blocklist-updater` Cargo feature. Run
its local tests with:

```sh
cargo test --features blocklist-updater --bin update-blocklist
```

## Initial local measurements

On 2026-11-18, on one Linux development host with Rust 1.100.0, the Python
parser's median over 20 warm iterations of the 195,795-byte checked-in list
was 21.526 ms; the Rust release parser's median over 20 iterations was 2.865
ms. These isolate parsing, not workflow time.

Three alternating local execution samples were not taken: three Python runs
were followed by three Rust runs against the real read-only upstream sources,
each starting from isolated copies of the same assets. Median elapsed times
were 0.341 s for Python and 0.188 s for the prebuilt Rust binary. All six
produced SHA-256 `999d0e3ac11cd1f4dc7be953eae26621b36a1cac5d67eb00e8fc84be953186ba`.
Network variability and run order limit this comparison.

The first local release build of the candidate took 40.377 s with some
previously cached dependencies. It adds HTTP/TLS dependencies and may make
the scheduled workflow slower even though the prebuilt program runs faster.
This is not a controlled cold CI comparison. The Python reference's in-memory
candidate build on the same downloaded snapshots took a median of 61.972 ms
over 20 iterations. The Rust candidate matched its output byte-for-byte.

The draft PR's first GitHub Actions CI run at commit `b1d284a` took 96 seconds
from job setup to completion. Its new Rust updater test step took 30 seconds,
including compilation; this is not the scheduled update workflow and is not a
controlled cold-versus-warm experiment.

## Prebuilt release option

Publishing the updater as a release asset could remove its compilation from
the scheduled update job. This repository had no GitHub releases or
release-publishing workflow when checked on 2026-11-18, so it would first need
a release process. A tag or `latest` URL alone is not sufficient to establish
what code is being executed.

Before adopting a prebuilt updater, define and test a trusted release process:
bind the artifact to its source revision and dependencies, verify provenance
and integrity before execution, pin the intended release and expected
artifact identity in trusted repository configuration, and fail closed when
verification fails or updater source changes without a corresponding release.
Account for architecture and availability, and never fall back silently to an
older or unverified binary. The current scheduled workflow also runs Rust
tests of the application; a prebuilt updater does not remove that separate
compilation. Measure the complete job, not only updater startup.

A local packaging rehearsal built the updater with `--locked`, packed the
Linux executable and a SHA-256 manifest into a roughly 2 MiB archive,
verified the extracted binary, then ran it against an isolated checkout copy
using `--root`. It generated 13,578 entries (136 added, 38 removed) without
touching the working tree. This tests portability of the binary on the same
host, not release provenance or compatibility with the GitHub runner.

## Before replacing the existing scripts

- Complete differential and integration coverage for all success, failure,
  timeout, malformed input, size, protected-domain, exclusion, atomic write,
  and source failure paths. The existing Python tests remain authoritative.
- The Rust HTTP integration test now verifies that a failed or stalled download, an
  oversized or undersized source, and an excluded-but-protected domain never
  replace the existing file. It also checks successful publication with both
  sources. Remaining differential cases still need coverage.
- The prebuilt executable accepts `--root DIRECTORY` (default: current
  directory) so it does not depend on the checkout where it was compiled.
- Measure end-to-end GitHub Actions duration for cold and warm caches, with
  equivalent validation, including compilation. Optimize or change the
  packaging strategy if it increases total workflow time.
- Migrate the workflow, CI, tests, documentation and remaining scripts only
  after those checks pass; do not weaken fail-closed blocklist protections.
