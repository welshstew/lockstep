#!/usr/bin/env bash
# Publish the current HEAD to the public GitHub repository as a single snapshot commit.
#
#   scripts/publish-github.sh git@github.com:<owner>/lockstep.git "Your Name" <id>+<user>@users.noreply.github.com ["message"]
#
# The private development history stays where it is: GitHub gets one commit per publish,
# whose tree is exactly HEAD's, on top of what's already there (or as the first commit).
# Run it from a clean main.
set -euo pipefail

REMOTE=${1:?usage: $0 <remote-url> <author name> <author email> [message]}
NAME=${2:?author name}
EMAIL=${3:?author email (use your GitHub noreply address)}
MSG=${4:-}
cd "$(dirname "$0")/.."

[[ -z $(git status --porcelain --untracked-files=no) ]] || { echo "working tree has changes; commit or stash first" >&2; exit 1; }
# Literal placeholders only: "$OWNER/lockstep" and "${OWNER}/..." in scripts are shell variables.
placeholder='(^|[^$A-Za-z_{])OWNER/lockstep'
if git grep -nE "$placeholder" -- . ':!scripts/publish-github.sh' >/dev/null; then
  echo "replace the OWNER placeholders first:" >&2; git grep -nE "$placeholder" -- . ':!scripts/publish-github.sh' >&2; exit 1
fi
if git grep -nI -E "100\.123\.|tailec806|/Users/" -- . ':!scripts/publish-github.sh' >/dev/null; then
  echo "internal addresses or local paths found:" >&2; git grep -nI -E "100\.123\.|tailec806|/Users/" -- . ':!scripts/publish-github.sh' >&2; exit 1
fi

tree=$(git rev-parse "HEAD^{tree}")
parent=()  # bash 3.2 (macOS) treats an empty array as unset under set -u, hence the ${x[@]+...} form below
if git fetch -q "$REMOTE" main 2>/dev/null; then
  parent=(-p FETCH_HEAD)
  [[ $(git rev-parse "FETCH_HEAD^{tree}") == "$tree" ]] && { echo "GitHub already has this tree"; exit 0; }
  MSG=${MSG:-"Update to $(git rev-parse --short HEAD)"}
else
  MSG=${MSG:-"Initial public release"}
fi

commit=$(GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL" GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL" \
  git commit-tree "$tree" ${parent[@]+"${parent[@]}"} -m "$MSG")
echo "pushing $commit (tree of $(git rev-parse --short HEAD)) to $REMOTE main"
git push "$REMOTE" "$commit:refs/heads/main"
