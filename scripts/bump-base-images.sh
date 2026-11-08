#!/usr/bin/env bash
# Update every digest-pinned Red Hat Hardened Image reference to the tag's current digest.
# The images are rebuilt with security fixes almost daily, so run this (then `make scan`)
# regularly, or let Renovate do it. A pin with no tag (e.g. hi/dex@sha256:…) tracks :latest.
set -euo pipefail
cd "$(dirname "$0")/.."
FILES=(Dockerfile dev/seed/Dockerfile dev/dex/Dockerfile compose.yaml)
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
grep -hoE 'registry\.access\.redhat\.com/hi/[a-z0-9-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}' "${FILES[@]}" | sort -u |
while read -r ref; do
  repo=${ref%@*}; old=${ref#*@}
  name=${repo#registry.access.redhat.com/}; tag=latest
  [[ $name == *:* ]] && { tag=${name#*:}; name=${name%%:*}; }
  new=$(curl -fsSI -H "Accept: $ACCEPT" "https://registry.access.redhat.com/v2/$name/manifests/$tag" |
        awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r')
  if [[ -z $new ]]; then echo "!! could not resolve $name:$tag"; continue; fi
  if [[ $new == "$old" ]]; then echo "   $name:$tag up to date"; continue; fi
  echo "-> $name:$tag ${old:7:12} -> ${new:7:12}"
  sed -i.bak "s|$repo@$old|$repo@$new|g" "${FILES[@]}" && rm -f "${FILES[@]/%/.bak}"
done
