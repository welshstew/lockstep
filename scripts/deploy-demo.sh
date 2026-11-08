#!/usr/bin/env bash
# Deploy the public demo (deploy/demo/compose.yaml) to a Docker host over SSH.
#
#   scripts/deploy-demo.sh root@203.0.113.10 [domain]
#
# Copies the repository to /opt/lockstep, creates /opt/lockstep/.env with random secrets on
# the first run (kept on later runs, never printed), renders the Dex config, and (re)starts
# the stack. Needs rsync locally, and Docker with the compose plugin on the server.
set -euo pipefail

TARGET=${1:?usage: $0 user@host [domain]}
DOMAIN=${2:-getlockstep.cloud}
DIR=${DEPLOY_DIR:-/opt/lockstep}
cd "$(dirname "$0")/.."

ssh "$TARGET" "mkdir -p '$DIR' && chmod 700 '$DIR'"
rsync -az --delete \
  --exclude .git --exclude .env --exclude dex.yaml --exclude node_modules --exclude frontend/dist \
  --exclude .venv --exclude reports --exclude '__pycache__' --exclude .pytest_cache --exclude docs/images \
  ./ "$TARGET:$DIR/"

ssh "$TARGET" DIR="$DIR" DOMAIN="$DOMAIN" bash -s <<'REMOTE'
set -euo pipefail
cd "$DIR"
umask 077
rand() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
if [ ! -f .env ]; then
  cat > .env <<ENV
APEX_HOST=$DOMAIN
DEMO_HOST=demo.$DOMAIN
LOGIN_HOST=login.$DOMAIN
RESEED_INTERVAL=3600
LOCKSTEP_SESSION_KEY=$(rand)
VAULT_A_TOKEN=$(rand)
VAULT_B_TOKEN=$(rand)
DEX_CLIENT_SECRET=$(rand)
ENV
  echo "created $DIR/.env with new secrets"
fi
set -a; . ./.env; set +a
# Dex doesn't expand environment variables in its config, so render it here.
sed -e "s|\${LOGIN_HOST}|$LOGIN_HOST|g" -e "s|\${DEMO_HOST}|$DEMO_HOST|g" \
    -e "s|\${DEX_CLIENT_SECRET}|$DEX_CLIENT_SECRET|g" deploy/demo/dex.yaml.tmpl > dex.yaml
chown 65532:65532 dex.yaml && chmod 600 dex.yaml
docker compose -f deploy/demo/compose.yaml --project-directory . up -d --build --remove-orphans
docker compose -f deploy/demo/compose.yaml --project-directory . ps
REMOTE
