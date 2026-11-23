#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --disarm ]]; then
  pending=$(gh pr list --repo "$GITHUB_REPOSITORY" --base main \
    --head automation/update-blocklist --state open --json id,author,autoMergeRequest,isCrossRepository)
  node=$(jq -er --arg author "${APP_SLUG}[bot]" '
    map(select(.autoMergeRequest != null))
    | if length == 0 then ""
      elif length == 1 and .[0].author.login == $author and (.[0].isCrossRepository | not)
      then .[0].id else error("Unexpected armed PR on the automation branch") end
  ' <<< "$pending")
  if [[ -n "$node" ]]; then
    gh api graphql -f id="$node" -f query='
      mutation($id: ID!) {
        disablePullRequestAutoMerge(input: {pullRequestId: $id}) {
          pullRequest { number }
        }
      }
    ' >/dev/null
  fi
  exit 0
fi

if [[ "$(gh api "repos/$GITHUB_REPOSITORY" --jq .allow_auto_merge)" != true ]]; then
  echo "::notice::Native auto-merge is disabled; leaving this PR for manual review."
  exit 0
fi

rules=$(gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/rules/branches/main")
if ! jq -e '
  add as $rules
  | any($rules[]; .type == "pull_request"
      and .parameters.required_approving_review_count >= 1
      and .parameters.dismiss_stale_reviews_on_push
      and (.parameters.allowed_merge_methods | index("merge") != null))
    and any($rules[]; .type == "required_status_checks"
      and .parameters.strict_required_status_checks_policy
      and ([.parameters.required_status_checks[]
           | select(.integration_id == 15368) | .context]
           | contains(["check", "blocklist-safety", "cururu-validated"])))
' <<< "$rules" >/dev/null; then
  echo "::notice::The required approval and check rules are not active; leaving this PR for manual review."
  exit 0
fi

pr=$(gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER")
node=$(jq -er --arg repo "$GITHUB_REPOSITORY" --arg author "${APP_SLUG}[bot]" --arg sha "$HEAD_SHA" '
  select(.state == "open" and .draft == false and .user.login == $author
    and .head.repo.full_name == $repo and .base.repo.full_name == $repo
    and .head.ref == "automation/update-blocklist" and .base.ref == "main"
    and .head.sha == $sha) | .node_id
' <<< "$pr")
files=$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/files" --jq '.[].filename')
test "$files" = assets/blocklist.txt
blob=$(gh api "repos/$GITHUB_REPOSITORY/contents/assets/blocklist.txt?ref=$HEAD_SHA" --jq .sha)
test "$blob" = "$CANDIDATE_BLOB"
test "$(gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER" --jq .head.sha)" = "$HEAD_SHA"

# This mutation only enables native auto-merge. Never fall back to a direct
# merge if GitHub rejects the request or its branch policy has changed.
gh api graphql -f id="$node" -f query='
  mutation($id: ID!) {
    enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: MERGE}) {
      pullRequest { number autoMergeRequest { mergeMethod } }
    }
  }
' --jq '.data.enablePullRequestAutoMerge.pullRequest'
