#!/usr/bin/env bash
set -euo pipefail

# The merge API only pins the head. Require GitHub to enforce up-to-date
# checks in a separate ruleset that the App cannot bypass.
rules=$(gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/rules/branches/main")
strict_rulesets=$(jq -er '
  add | map(select(.type == "required_status_checks"
    and .parameters.strict_required_status_checks_policy == true
    and ([.parameters.required_status_checks[]
          | select(.integration_id == 15368) | .context]
          | contains(["check", "blocklist-safety"]))))
  | map(.ruleset_id | select(type == "number")) | unique | .[]
' <<< "$rules") || {
  echo "::error::Missing a strict CI and safety ruleset; refusing automatic merge."
  exit 1
}
enforced=false
while IFS= read -r ruleset_id; do
  bypass=$(gh api "repos/$GITHUB_REPOSITORY/rulesets/$ruleset_id?includes_parents=true" \
    --jq .current_user_can_bypass)
  if [[ "$bypass" == never ]]; then
    enforced=true
    break
  fi
done <<< "$strict_rulesets"
if [[ "$enforced" != true ]]; then
  echo "::error::The App can bypass the strict checks or GitHub did not confirm otherwise."
  exit 1
fi

# Only called after the current run validated the candidate and both PR checks.
# Revalidate identity and content before using the App's PR-only exception.
pr=$(gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER")
if ! jq -e --arg repo "$GITHUB_REPOSITORY" --arg author "${APP_SLUG}[bot]" \
    --arg head "$HEAD_SHA" --arg base "$GITHUB_SHA" '
  .state == "open" and .draft == false and .user.login == $author
  and .head.repo.full_name == $repo and .base.repo.full_name == $repo
  and .head.ref == "automation/update-blocklist" and .base.ref == "main"
  and .head.sha == $head and .base.sha == $base
' <<< "$pr" >/dev/null; then
  echo "::error::The PR is not the expected App update at the reviewed head and base."
  exit 1
fi

files=$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/files" --jq '.[].filename')
test "$files" = assets/blocklist.txt
blob=$(gh api "repos/$GITHUB_REPOSITORY/contents/assets/blocklist.txt?ref=$HEAD_SHA" --jq .sha)
test "$blob" = "$CANDIDATE_BLOB"
parents=$(gh api "repos/$GITHUB_REPOSITORY/commits/$HEAD_SHA" --jq '.parents[].sha')
test "$parents" = "$GITHUB_SHA"
test "$(gh api "repos/$GITHUB_REPOSITORY/branches/main" --jq .commit.sha)" = "$GITHUB_SHA"

# The API checks the head SHA atomically. If the head changed, do not retry
# with the new head: it needs a fresh validation and review.
result=$(gh api --method PUT "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/merge" \
  -f sha="$HEAD_SHA" -f merge_method=merge)
merge_sha=$(jq -er 'select(.merged == true) | .sha | select(test("^[0-9a-f]{40}$"))' <<< "$result")
merged_parents=$(gh api "repos/$GITHUB_REPOSITORY/commits/$merge_sha" --jq '.parents[].sha')
if [[ "$merged_parents" != "$GITHUB_SHA"$'\n'"$HEAD_SHA" ]]; then
  echo "::error::GitHub merged $merge_sha, but its parents do not match the validated base and head. Inspect the merge; no automatic rollback was attempted."
  exit 1
fi
echo "Merged reviewed blocklist: $merge_sha"
