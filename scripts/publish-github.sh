#!/usr/bin/env bash
# Publish the current HEAD to the public GitHub repository as a single snapshot commit.
#
#   scripts/publish-github.sh git@github.com:<owner>/lockstep.git "Your Name" <id>+<user>@users.noreply.github.com ["message"]
#
# The private development history stays where it is: GitHub gets one commit per publish,
# whose tree is HEAD's minus the private paths below, on top of what's already there (or as
# the first commit). Run it from a clean main. PUBLISH_DRY_RUN=1 builds and checks the tree,
# and lists what's left out, without pushing.
set -euo pipefail

REMOTE=${1:?usage: $0 <remote-url> <author name> <author email> [message]}
NAME=${2:?author name}
EMAIL=${3:?author email (use your GitHub noreply address)}
MSG=${4:-}
cd "$(dirname "$0")/.."
# Kept in the private repository (Gitea) only: never part of what GitHub gets.
PRIVATE_PATHS=(private)
not_private=(); for p in "${PRIVATE_PATHS[@]}"; do not_private+=(":!$p"); done

[[ -z $(git status --porcelain --untracked-files=no) ]] || { echo "working tree has changes; commit or stash first" >&2; exit 1; }
# Literal placeholders only: "$OWNER/lockstep" and "${OWNER}/..." in scripts are shell variables.
placeholder='(^|[^$A-Za-z_{])OWNER/lockstep'
if git grep -nE "$placeholder" -- . ':!scripts/publish-github.sh' "${not_private[@]}" >/dev/null; then
  echo "replace the OWNER placeholders first:" >&2; git grep -nE "$placeholder" -- . ':!scripts/publish-github.sh' "${not_private[@]}" >&2; exit 1
fi
if git grep -nI -E "100\.123\.|tailec806|/Users/" -- . ':!scripts/publish-github.sh' "${not_private[@]}" >/dev/null; then
  echo "internal addresses or local paths found:" >&2; git grep -nI -E "100\.123\.|tailec806|/Users/" -- . ':!scripts/publish-github.sh' "${not_private[@]}" >&2; exit 1
fi

# HEAD's tree without the private paths, built in a throwaway index (the real one is untouched)
index=$(mktemp); trap 'rm -f "$index"' EXIT
GIT_INDEX_FILE=$index git read-tree HEAD
GIT_INDEX_FILE=$index git rm -r -q --cached --ignore-unmatch -- "${PRIVATE_PATHS[@]}"
tree=$(GIT_INDEX_FILE=$index git write-tree)
for p in "${PRIVATE_PATHS[@]}"; do
  if git ls-tree -r --name-only "$tree" -- "$p" | grep -q .; then
    echo "refusing to publish: $p/ is still in the tree" >&2; exit 1
  fi
done
left_out=$(git ls-tree -r --name-only HEAD -- "${PRIVATE_PATHS[@]}" | wc -l | tr -d ' ')
echo "publishing the tree of $(git rev-parse --short HEAD) without ${PRIVATE_PATHS[*]}/ ($left_out files left out)"
parent=()  # bash 3.2 (macOS) treats an empty array as unset under set -u, hence the ${x[@]+...} form below
if git fetch -q "$REMOTE" main 2>/dev/null; then
  parent=(-p FETCH_HEAD)
  [[ $(git rev-parse "FETCH_HEAD^{tree}") == "$tree" ]] && { echo "GitHub already has this tree"; exit 0; }
  MSG=${MSG:-"Update to $(git rev-parse --short HEAD)"}
else
  MSG=${MSG:-"Initial public release"}
fi

if [[ ${PUBLISH_DRY_RUN:-0} == 1 ]]; then
  echo "dry run: would push tree $tree to $REMOTE main; left out:"; git ls-tree -r --name-only HEAD -- "${PRIVATE_PATHS[@]}" | sed 's/^/  /'
  exit 0
fi
commit=$(GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL" GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL" \
  git commit-tree "$tree" ${parent[@]+"${parent[@]}"} -m "$MSG")
echo "pushing $commit (tree of $(git rev-parse --short HEAD)) to $REMOTE main"
git push "$REMOTE" "$commit:refs/heads/main"
