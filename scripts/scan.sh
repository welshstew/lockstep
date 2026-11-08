#!/usr/bin/env bash
# Security scan of Lockstep. Writes everything to reports/.
#
#   make scan                 # all scanners, in pinned containers (podman, or docker)
#   SCAN_NATIVE=1 make scan   # use trivy/gitleaks/pip-audit/bandit/npm from PATH (CI)
#
# Scanners: cosign (base image signatures), Grype (image), Trivy (image + filesystem),
# pip-audit, npm audit, bandit, gitleaks.
# Every tool writes its full report. The pass/fail gate is applied afterwards by
# scan/summarize.py, so local runs and CI fail on exactly the same findings:
#   - base images: every Red Hat Hardened Image must pass cosign signature verification
#   - Grype / Trivy vulnerabilities: HIGH/CRITICAL with a fixed version available
#   - Grype must detect the image OS (otherwise OS packages went unscanned)
#   - Trivy misconfigurations: HIGH/CRITICAL
#   - pip-audit: any vulnerability with a fix version
#   - npm audit: HIGH/CRITICAL in production dependencies with a fix available
#   - bandit: HIGH severity with MEDIUM+ confidence
#   - gitleaks: any finding in git history
# Allowlists: .grype.yaml (reason must end 'until YYYY-MM-DD'), .trivyignore.yaml, scan/pip-audit-ignore.txt, .gitleaks.toml, [tool.bandit] in backend/pyproject.toml
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source scan/versions.env

R=reports
IMAGE=${SCAN_IMAGE:-lockstep:scan}
ENGINE=${CONTAINER_ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}
NATIVE=${SCAN_NATIVE:-0}
mkdir -p "$R" "$R/.cache"
rm -f "$R"/*.json "$R"/*.sarif "$R"/*.txt "$R"/*.md

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# run <image> <cmd...>: run a command with the repo at the current directory, natively or in a container.
run() {
  local image=$1; shift
  if [[ $NATIVE == 1 ]]; then
    "$@"
  else
    # The command's first word becomes the entrypoint, so images with their own entrypoint
    # (trivy, gitleaks) behave the same as plain ones (python, node).
    "$ENGINE" run --rm -v "$PWD:/src:Z" -w /src \
      -v "$PWD/$R/.cache:/cache:Z" -e TRIVY_CACHE_DIR=/cache/trivy -e npm_config_cache=/cache/npm \
      -e PIP_CACHE_DIR=/cache/pip -e GRYPE_DB_CACHE_DIR=/cache/grype --entrypoint "$1" "$image" "${@:2}"
  fi
}

[[ $NATIVE == 1 ]] && export TRIVY_CACHE_DIR=$R/.cache/trivy

# ---------------------------------------------------------------- pins
log "Checking image pins are multi-arch indexes (amd64 + arm64)"
python3 scripts/pin-scanner-images.py --check || { echo "Fix with: make pin-scanner-images / make bump-base-images"; exit 2; }

# ---------------------------------------------------------------- base image signatures
log "cosign: verify Red Hat Hardened Image signatures"
COSIGN=$([[ $NATIVE == 1 ]] && echo cosign || echo /usr/bin/cosign)
echo "[]" > "$R/cosign.json"
for ref in $(grep -hoE 'registry\.access\.redhat\.com/hi/[^ "]+@sha256:[0-9a-f]{64}' Dockerfile dev/*/Dockerfile compose.yaml deploy/*/compose.yaml | sort -u); do
  ok=false
  for attempt in 1 2 3; do  # registry hiccups shouldn't fail the gate; a bad signature fails every time
    if run "$COSIGN_IMG" "$COSIGN" verify --key "$RH_SIGNING_KEY" --insecure-ignore-tlog "$ref" >/dev/null 2>"$R/.cache/cosign.err"; then
      ok=true; break
    fi
    [[ $attempt -lt 3 ]] && sleep 5
  done
  [[ $ok == true ]] || cat "$R/.cache/cosign.err"
  echo "  $ref -> verified=$ok"
  python3 -c "import json,sys;p=sys.argv[1];d=json.load(open(p));d.append({'image':sys.argv[2],'verified':sys.argv[3]=='true'});json.dump(d,open(p,'w'))" "$R/cosign.json" "$ref" "$ok"
done

# ---------------------------------------------------------------- image
if [[ -z ${SCAN_SKIP_BUILD:-} ]]; then
  log "Building app image $IMAGE"
  "$ENGINE" build -q -t "$IMAGE" . || { echo "image build failed"; exit 2; }
fi
log "Exporting image for Trivy"
rm -f "$R/.cache/image.tar"
"$ENGINE" save -o "$R/.cache/image.tar" "$IMAGE" || { echo "image save failed"; exit 2; }

log "Trivy: image vulnerabilities"
run "$TRIVY_IMG" trivy image --quiet --input "$R/.cache/image.tar" --scanners vuln \
  --ignorefile .trivyignore.yaml --format json --output "$R/trivy-image.json"
run "$TRIVY_IMG" trivy convert --format sarif --output "$R/trivy-image.sarif" "$R/trivy-image.json"
run "$TRIVY_IMG" trivy convert --format table --output "$R/trivy-image.txt" "$R/trivy-image.json"

# Grype understands Hummingbird / Red Hat Hardened Images OS packages; Trivy 0.76 does not
# (trivy discussion #11180), so Grype is the authoritative image scanner.
log "Grype: image vulnerabilities (OS + language packages)"
GRYPE=$([[ $NATIVE == 1 ]] && echo grype || echo /grype)
GRYPE_DB_CACHE_DIR=$([[ $NATIVE == 1 ]] && echo "$R/.cache/grype" || echo /cache/grype)
if [[ $NATIVE == 1 ]]; then export GRYPE_DB_CACHE_DIR; fi
run "$GRYPE_IMG" "$GRYPE" "docker-archive:$R/.cache/image.tar" --quiet --config .grype.yaml \
  -o "json=$R/grype-image.json" -o "sarif=$R/grype-image.sarif" -o "table=$R/grype-image.txt"

# ---------------------------------------------------------------- filesystem
log "Trivy: filesystem (lockfiles + Dockerfile/IaC misconfiguration)"
run "$TRIVY_IMG" trivy fs --quiet --scanners vuln,misconfig --ignorefile .trivyignore.yaml \
  --skip-dirs frontend/node_modules --skip-dirs frontend/dist --skip-dirs reports \
  --format json --output "$R/trivy-fs.json" .
run "$TRIVY_IMG" trivy convert --format sarif --output "$R/trivy-fs.sarif" "$R/trivy-fs.json"
run "$TRIVY_IMG" trivy convert --format table --output "$R/trivy-fs.txt" "$R/trivy-fs.json"
# Trivy skips any directory named "dev" by default (it's meant for /dev when scanning a root
# filesystem), which would silently exclude our dev/ tooling. Scan it as its own target.
log "Trivy: dev/ tooling (seed, e2e and k8s Dockerfiles)"
run "$TRIVY_IMG" trivy config --quiet --ignorefile .trivyignore.yaml --format json --output "$R/trivy-dev.json" dev
run "$TRIVY_IMG" trivy convert --format sarif --output "$R/trivy-dev.sarif" "$R/trivy-dev.json"

# Trivy renders a Helm chart with its default values, and our chart (rightly) refuses empty
# defaults, so a plain fs scan only logs a warning and skips the chart. Scan it explicitly
# with the minimal values (the secure defaults) and the everything-on values.
for v in minimal full; do
  log "Trivy: Helm chart with ci/$v-values.yaml"
  run "$TRIVY_IMG" trivy config --quiet --ignorefile .trivyignore.yaml \
    --helm-values "charts/lockstep/ci/$v-values.yaml" --format json --output "$R/trivy-chart-$v.json" charts/lockstep
  run "$TRIVY_IMG" trivy convert --format sarif --output "$R/trivy-chart-$v.sarif" "$R/trivy-chart-$v.json"
done

# ---------------------------------------------------------------- python deps
log "pip-audit: backend dependencies (resolved from backend/pyproject.toml)"
IGNORES=$(grep -Ev '^\s*(#|$)' scan/pip-audit-ignore.txt | awk '{printf " --ignore-vuln %s", $1}')
if [[ $NATIVE == 1 ]]; then
  # shellcheck disable=SC2086
  pip-audit --progress-spinner off $IGNORES -f json -o "$R/pip-audit.json" ./backend
else
  run "$PYTHON_IMAGE" sh -c "pip install -q --root-user-action=ignore pip-audit==$PIP_AUDIT_VERSION && \
    pip-audit --progress-spinner off $IGNORES -f json -o $R/pip-audit.json ./backend"
fi

# ---------------------------------------------------------------- node deps
log "npm audit: frontend dependencies"
run "$NODE_IMAGE" sh -c "cd frontend && npm audit --json > ../$R/npm-audit.json; \
  npm audit --omit=dev --json > ../$R/npm-audit-prod.json; true"

# ---------------------------------------------------------------- python SAST
log "bandit: backend + seed source"
BANDIT_ARGS="-r backend/src dev/seed -c backend/pyproject.toml -q"
if [[ $NATIVE == 1 ]]; then
  bandit $BANDIT_ARGS -f json -o "$R/bandit.json"
  bandit $BANDIT_ARGS -f sarif -o "$R/bandit.sarif"
else
  run "$PYTHON_IMAGE" sh -c "pip install -q --root-user-action=ignore 'bandit[sarif,toml]==$BANDIT_VERSION' && \
    bandit $BANDIT_ARGS -f json -o $R/bandit.json; bandit $BANDIT_ARGS -f sarif -o $R/bandit.sarif; true"
fi

# ---------------------------------------------------------------- secrets
log "gitleaks: git history"
if [[ $NATIVE == 1 ]]; then
  gitleaks git --no-banner --config .gitleaks.toml --redact --exit-code 0 \
    --report-format sarif --report-path "$R/gitleaks.sarif" .
  gitleaks git --no-banner --config .gitleaks.toml --redact --exit-code 0 \
    --report-format json --report-path "$R/gitleaks.json" .
else
  # The container runs as another user, so tell git the mounted repo is safe to read.
  "$ENGINE" run --rm -v "$PWD:/src:Z" -w /src --entrypoint sh "$GITLEAKS_IMG" -c "
    git config --global --add safe.directory /src &&
    gitleaks git --no-banner --config .gitleaks.toml --redact --exit-code 0 --report-format sarif --report-path $R/gitleaks.sarif . &&
    gitleaks git --no-banner --config .gitleaks.toml --redact --exit-code 0 --report-format json --report-path $R/gitleaks.json ."
fi

# ---------------------------------------------------------------- gate
log "Summary"
python3 scan/summarize.py "$R"
