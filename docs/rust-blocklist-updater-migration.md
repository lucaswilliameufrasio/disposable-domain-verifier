# Rust blocklist updater: experimental migration

The scheduled workflow continues to use the Python updater and its tests.
The Rust updater remains available for experiments but is not on the
scheduled workflow's critical path.

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

`.github/workflows/updater-release.yml` is the manual release rehearsal, not
the scheduled updater. GitHub requires the workflow on the default branch
before it can be dispatched. Once reviewed and on protected `main`, it builds
and tests that exact revision without write credentials, attests the binary
in a separate publishing job, and creates a non-latest prerelease. Two
unprivileged jobs then run the Python and verified release candidates with the
same application validation. Use job timestamps, compare generated hashes and
the source hashes printed by each candidate, and discard comparisons where
upstream changed between jobs. These jobs exclude PR creation, Cururu, and
waiting for PR checks, so report those separately from the scheduled baseline.
No production workflow consumes a trial release.

For production, pin a specific release tag and source SHA in the trusted
workflow, enforce the signer workflow and source ref/digest, and verify
compatibility against updater source changes before execution. Do not use
`latest` or move a release tag. A successful trial is not authorization for
cutover.

## Native auto-merge without bypass

GitHub's native auto-merge is disabled for this repository. The `main`
ruleset requires one approval and allows merge commits; it does not currently
require status checks. The proposed rollout is:

1. Require `check`, `blocklist-safety` and a dedicated successful Cururu
   verdict for the exact reviewed head as GitHub status checks, restricted to
   their expected publisher. The generic `review` job can be skipped and must
   not be used as a substitute for the dedicated verdict.
2. Keep one eligible approval and ensure approvals cannot carry forward to
   unreviewed pushes. Require the head to be current with `main`. Enable
   **Allow auto-merge** without adding a bypass actor.
3. Arm auto-merge using the GitHub App only for its own blocklist-only PR
   after checking the author, branch, path, candidate blob, and current SHA.
   Use the normal merge method. When the app updates the head, revalidate it;
   the status checks and approval must apply to the new head.
4. Verify with a test PR that missing approval or a pending/failed check
   blocks integration, and that granting approval with all checks green
   allows GitHub to merge. Keep the existing manual review flow until tested.

The setting and ruleset updates are administrative changes, separate from
this draft and from any one-time administrative merge. Native auto-merge
automates integration *after* approval; it does not approve an unattended PR.

## Decision after the attested trial

In [run 45114608010](https://github.com/lucaswilliameufrasio/disposable-domain-verifier/actions/runs/45114608010),
the Python and attested Rust paths used identical upstream inputs and produced
the same blocklist. The consumer jobs took 48 s (Python) and 46 s (Rust);
candidate generation including required setup took 4 s and 5 s, respectively.
One comparison does not demonstrate an end-to-end gain, so keep Python for
scheduled runs. The separate manual release rehearsal remains available.

The [live blocklist run](https://github.com/lucaswilliameufrasio/disposable-domain-verifier/actions/runs/45107297962)
took 97 s, with 29 s of review and 31 s waiting for checks. The PR CI spent
22 s compiling benchmarks. As an alternative, split benchmark compilation
from validation, retain the required `check` name for the aggregate job, and
require explicit success from both jobs. Compare `check` completion times
before and after under similar cache conditions; do not treat a single run
as evidence of improvement.

## Before reconsidering replacement of the existing scripts

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
