#!/usr/bin/env bash
# Release notes for one version: its CHANGELOG.md section plus install instructions.
#   OWNER=<github owner> REPO=<owner/repo> [IMAGE_DIGEST=… CHART_DIGEST=…] scripts/release-notes.sh 0.2.0
set -euo pipefail
cd "$(dirname "$0")/.."
v=${1:?usage: $0 X.Y.Z}
OWNER=${OWNER:?} REPO=${REPO:?}

awk -v v="$v" '$0 ~ "^## \\[" v "\\]" {on=1; next} on && /^## \[/ {exit} on' CHANGELOG.md
cat <<NOTES

## Install

**Helm** (Kubernetes):

\`\`\`sh
helm upgrade --install lockstep oci://ghcr.io/$OWNER/charts/lockstep --version $v \\
  -n lockstep --create-namespace -f my-values.yaml
\`\`\`

**Container image** (\`linux/amd64\`, \`linux/arm64\`):

\`\`\`sh
docker pull ghcr.io/$OWNER/lockstep:$v
\`\`\`

**Command line** (Python 3.13+), from GitHub or from the image:

\`\`\`sh
pipx install "git+https://github.com/$REPO@v$v#subdirectory=backend"
docker run --rm -it --entrypoint lockstep -e VAULT_ADDR -e VAULT_TOKEN ghcr.io/$OWNER/lockstep:$v --help
\`\`\`
${IMAGE_DIGEST:+
Image digest: \`$IMAGE_DIGEST\`${CHART_DIGEST:+ · chart digest: \`$CHART_DIGEST\`}
}
## Verify

The image and the chart are signed with [cosign](https://docs.sigstore.dev/) (keyless, by this repository's release workflow), and the image carries an SBOM and build provenance:

\`\`\`sh
cosign verify ghcr.io/$OWNER/lockstep:$v \\
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$v" \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
\`\`\`
NOTES
