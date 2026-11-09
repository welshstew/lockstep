#!/usr/bin/env bash
# Build getlockstep.cloud's docs and guide pages and sitemap (see scripts/build_site.py).
# Keeps the Markdown library in .venv-site/ (gitignored), created on the first run.
set -euo pipefail
cd "$(dirname "$0")/.."
MARKDOWN_VERSION=3.11.2
if ! .venv-site/bin/python -c "import markdown, sys; sys.exit(markdown.__version__ != '$MARKDOWN_VERSION')" 2>/dev/null; then
  python3 -m venv .venv-site
  .venv-site/bin/pip install -q --disable-pip-version-check "markdown==$MARKDOWN_VERSION"
fi
.venv-site/bin/python -I scripts/build_site.py
