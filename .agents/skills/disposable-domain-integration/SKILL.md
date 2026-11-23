---
name: disposable-domain-integration
description: Integrate the Disposable Domain Verifier API into signup or email-change flows and audit existing account databases for disposable email domains. Use for single and batch checks, compact bitset decoding, or read-only scans of account tables and exports that need a list of affected accounts without sending full email addresses.
---

# Disposable Domain Verifier integration

## Pick the interface

- For signup or email changes, parse the address locally with the application's email validator. Send only the hostname to `GET /v1/domains/verify?domain=…` (URL-encode it). Use `/v1/domains/verify/compact` for `200` with exactly `b"1"` or `b"0"`; use JSON if source and timestamp matter.
- For multiple domains, start with `POST /v1/domains/verify/batch` and JSON `{"domains":["mailinator.com","example.com"]}`. A `200` returns `{"results":[true,false]}` in input order. Prefer this format for straightforward debugging.
- For bandwidth-sensitive clients, send the same JSON to `POST /v1/domains/verify/batch/compact`. A `200` returns `application/octet-stream`. With `n` requested domains, require exactly `(n + 7) // 8` bytes. For item `i` use `bool(body[i // 8] & (1 << (i % 8)))`; unused high bits of the final byte must be zero.
- For both POSTs use `Content-Type: application/json`, 1–100 domains, and no more than 32 KiB. Always check HTTP status, response format, and result length before mapping results. Errors are JSON, including on compact routes. A bad domain rejects the entire batch; the error message reports its zero-based index.
- Use a configured HTTPS base URL, timeouts, and a bounded connection pool. Handle transient connection errors, `429`, and transient `5xx` with bounded backoff and honor `Retry-After`; do not retry other `4xx` without fixing the request. Do not turn an error into `not_listed`. During signup, explicitly choose what to do when classification is unavailable (e.g. hold for retry or continue pending normal email verification).

## Audit existing accounts without changing them

1. Confirm authorization and scope. Use a read-only connection or protected export. Read only the primary key and email address, or the key and stored validated domain if available. Use keyset pagination on an indexed stable ID (`id > last_id`, ordered by `id`); use a consistent snapshot or documented high-water mark for reproducibility.
2. Parse with the existing email parser, locally. Lowercase the hostname; convert internationalized names to ASCII IDNA with the project's trusted library, then validate hostname syntax. Record missing or invalid values separately. Preserve full subdomain names: the service uses exact matches, not registrable-domain or suffix matches.
3. Deduplicate normalized domains, not accounts. For small datasets, keep a dictionary of `domain → verdict` and join it back to each account. For large datasets, stage `(account_id, normalized_domain)` in a restricted local analysis store, stream distinct domains in groups of at most 100, and persist verdicts keyed by domain. Use bounded concurrency and reuse HTTP connections. Checkpoint completed groups for resume; store invalid and still-unverified domains with distinct statuses.
4. Join each verdict back to **all** affected account IDs. Report `listed`, `not_listed`, `invalid_or_missing`, and `unverified` separately, with counts of accounts and unique domains. Include scan time and matching source; if using a pinned blocklist, record its commit and SHA-256. Export only the necessary account IDs, classification, and domains if authorized. Do not send account IDs or full emails to the service or log them.
5. Deliver a review list, not a deletion or suspension script. A listed domain is a signal that the account uses a domain classified as disposable, not proof of abuse or current mailbox ownership. An unlisted domain is not proof of deliverability or permanence. Keep any remediation subject to a separate decision.

## When a local join is faster

For very large or privacy-sensitive scans, use `assets/blocklist.txt` from a trusted pinned revision, verify the expected hash, load normalized entries into a set (or stage them in an indexed local table), and match exact domains locally. Pin the same version the deployed API loaded if parity with production matters. Check representative listed, unlisted, uppercase, invalid, and subdomain cases before scanning the base. Do not call third-party services for every email or upload the account export.

## Verify the integration

- Try a listed and an unlisted domain and confirm repeated domains map to every account that uses them.
- For a binary client, test nine domains with matches at indices 0, 7 and 8; expect bytes `81 01` in hex. Reject truncated or unexpectedly long responses.
- Simulate invalid email and a failed API batch. Neither should be reported as `not_listed` or included among confirmed matches.
- Reconcile input accounts against the four output classifications before sharing the report.
