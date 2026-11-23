# Native auto-merge for disposable blocklist updates

This change is off by default. Existing repository rules require one
approval but do not dismiss it on new pushes or require CI statuses.
Do not set `BLOCKLIST_NATIVE_AUTO_MERGE` until the steps below are complete.

1. Merge this workflow through the normal review process. Let a blocklist
   update and a normal PR run so GitHub has observed the check names and
   publishers. A normal PR gets `cururu-validated` marked not applicable
   after its blocklist safety job; it still needs the required human approval.
2. On the active `main` ruleset, keep at least one approving review, enable
   dismissal of stale approvals, and require the branch to be up to date.
   Require `check`, `blocklist-safety`, and `cururu-validated`, all from
   GitHub Actions (integration ID `15368`). Do not add the automation app
   to the bypass list. Restrict writes to the automation branch to trusted
   actors; do not manually repoint an armed PR.
3. Enable **Allow auto-merge** in repository settings. Only then set the
   repository Actions variable `BLOCKLIST_NATIVE_AUTO_MERGE` to `true`.
4. Use a fresh automation PR to confirm that a missing approval or any
   missing/failing check prevents merge, and that an eligible approval
   with green checks produces a merge commit. Confirm the optional
   `autoMergeRequest` field is set before approving.

The workflow disarms an existing request before refreshing the App branch.
It publishes the verdict only after the candidate tests, scope checks,
completed Cururu quality gate and both PR checks pass. Before arming, it
checks the active ruleset and rechecks the PR identity, exact head and blob.
The GitHub GraphQL call only enables native auto-merge, never a direct
merge. If GitHub cannot arm the PR, leave it for normal human handling.

To turn off the automation, clear the variable and disable any outstanding
auto-merge request; keep required checks and approval protections in place.
