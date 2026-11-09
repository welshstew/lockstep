#!/usr/bin/env bash
# Check that a release tag matches every version in the repository, and that CHANGELOG.md
# has a section for it.  scripts/check-version.sh v0.2.0
set -euo pipefail
cd "$(dirname "$0")/.."
tag=${1:?usage: $0 vX.Y.Z}
v=${tag#v}
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "not a version tag: $tag" >&2; exit 1; }

fail=0
check() {  # check <what> <found>
  if [[ $2 == "$v" ]]; then echo "ok  $1 = $2"; else echo "!!  $1 = $2, tag says $v" >&2; fail=1; fi
}
check "charts/lockstep/Chart.yaml version" "$(sed -n 's/^version: *//p' charts/lockstep/Chart.yaml)"
check "charts/lockstep/Chart.yaml appVersion" "$(sed -n 's/^appVersion: *"\{0,1\}\([^"]*\)"\{0,1\}/\1/p' charts/lockstep/Chart.yaml)"
check "backend/pyproject.toml" "$(sed -n 's/^version = "\(.*\)"/\1/p' backend/pyproject.toml)"
check "frontend/package.json" "$(sed -n 's/^  "version": "\(.*\)",/\1/p' frontend/package.json)"
if grep -q "^## \[$v\]" CHANGELOG.md; then echo "ok  CHANGELOG.md has [$v]"; else echo "!!  CHANGELOG.md has no '## [$v]' section" >&2; fail=1; fi
exit $fail
