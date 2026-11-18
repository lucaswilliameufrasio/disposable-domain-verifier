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

## Before replacing the existing scripts

- Complete differential and integration coverage for all success, failure,
  timeout, malformed input, size, protected-domain, exclusion, atomic write,
  and source failure paths. The existing Python tests remain authoritative.
- Check command behavior and portability from different working directories.
- Measure end-to-end GitHub Actions duration for cold and warm caches, with
  equivalent validation, including compilation. Optimize or change the
  packaging strategy if it increases total workflow time.
- Migrate the workflow, CI, tests, documentation and remaining scripts only
  after those checks pass; do not weaken fail-closed blocklist protections.
