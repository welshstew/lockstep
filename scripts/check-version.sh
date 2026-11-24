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
check "charts/lockstep/Chart.yaml artifacthub.io/images" "$(sed -n 's|^ *image: ghcr.io/[^:]*/lockstep:||p' charts/lockstep/Chart.yaml)"
check "backend/pyproject.toml" "$(sed -n 's/^version = "\(.*\)"/\1/p' backend/pyproject.toml)"
check "frontend/package.json" "$(sed -n 's/^  "version": "\(.*\)",/\1/p' frontend/package.json)"
# Install commands and image tags people copy from the docs and the site: every one must name
# this release (dev/ and scripts/ use their own local tags and are left alone)
stale=$(git grep -n -E 'lockstep@v[0-9]+\.[0-9]+\.[0-9]+|welshstew/lockstep:[0-9]+\.[0-9]+\.[0-9]+|charts/lockstep --version [0-9]+\.[0-9]+\.[0-9]+|release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+' \
          -- README.md charts/lockstep/README.md docs deploy/demo/site/index.html \
        | grep -v -E "(lockstep@v|lockstep:|--version |refs/tags/v)$v([^0-9.]|\$)" || true)
if [[ -z $stale ]]; then echo "ok  install commands and image tags in the docs name $v"
else echo "!!  install commands or image tags in the docs name another version:" >&2; echo "$stale" >&2; fail=1; fi
if grep -q "^## \[$v\]" CHANGELOG.md; then echo "ok  CHANGELOG.md has [$v]"; else echo "!!  CHANGELOG.md has no '## [$v]' section" >&2; fail=1; fi
# Artifact Hub reads these annotations as YAML inside YAML: a description with ": " in it
# unquoted becomes a mapping and the whole package is rejected
if out=$(ruby -ryaml -e '
  ann = YAML.safe_load(File.read("charts/lockstep/Chart.yaml"))["annotations"] || {}
  kinds = %w[added changed deprecated removed fixed security]
  begin
    ch = YAML.safe_load(ann["artifacthub.io/changes"].to_s)
  rescue Psych::SyntaxError => e
    abort "artifacthub.io/changes is not valid YAML (quote descriptions that contain a colon): #{e.message}"
  end
  ok = ch.is_a?(Array) && !ch.empty? && ch.all? { |c| c.is_a?(Hash) && kinds.include?(c["kind"]) && c["description"].is_a?(String) }
  abort "artifacthub.io/changes must be a list of {kind, description} with string descriptions (quote them)" unless ok
  %w[artifacthub.io/links artifacthub.io/images].each { |k| YAML.safe_load(ann[k].to_s) if ann[k] }
  puts "#{ch.length} entries"' 2>&1); then
  echo "ok  Chart.yaml artifacthub.io annotations parse ($out)"
else
  echo "!!  Chart.yaml artifacthub.io annotations: $out" >&2; fail=1
fi
exit $fail
