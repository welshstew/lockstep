#!/usr/bin/env python3
"""Build the documentation and guide pages of getlockstep.cloud, plus its sitemap.

    scripts/build-site.sh          (sets up the Markdown library, then runs this)

Reads Markdown from docs/ and docs/guides/ and writes, next to the landing page:
    deploy/demo/site/docs/<name>/index.html      the guides listed in DOCS
    deploy/demo/site/guides/<name>/index.html    every docs/guides/*.md
    deploy/demo/site/docs/index.html             an index of both
    deploy/demo/site/sitemap.xml
    deploy/demo/site/schemas/*.json              copied from schemas/ (the CLI report's schema)
These are generated (gitignored); scripts/deploy-demo.sh builds them before copying.

A page's meta description comes from an HTML comment at its top,
<!-- description: ... --> (invisible on GitHub), or else its first paragraph.
Links between published pages become site links; links to anything else in the repository
go to GitHub. Images under docs/images are served by the site at /images.
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import markdown

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "deploy/demo/site"
BASE = "https://getlockstep.cloud"
REPO = "https://github.com/welshstew/lockstep"

# docs/<name>.md published at /docs/<name>/, in this order
DOCS = ["usage", "cli", "authentication", "configuration", "kubernetes", "security"]
# docs/guides/<name>.md published at /guides/<name>/: these first, in this order, then any others
GUIDES = ["compare-hashicorp-vault-clusters", "sync-vault-secrets-between-environments",
          "detect-vault-secret-drift-in-ci", "export-import-vault-secrets",
          "build-a-comparison-profile", "vault-jwt-login-from-ci"]


class Page:
    def __init__(self, src: Path, url: str, section: str):
        self.src, self.url, self.section = src, url, section
        self.text = src.read_text()
        m = re.search(r"^# (.+)$", self.text, re.M)
        self.title = m.group(1).strip() if m else src.stem
        m = re.search(r"<!--\s*description:\s*(.+?)\s*-->", self.text, re.S)
        self.description = re.sub(r"\s+", " ", m.group(1)) if m else _first_paragraph(self.text)

    @property
    def repo_path(self) -> str:
        return self.src.relative_to(ROOT).as_posix()


def _plain(md: str) -> str:
    md = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", md)
    md = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", md)
    md = re.sub(r"[`*_]", "", md)
    return re.sub(r"\s+", " ", md).strip()


def _first_paragraph(md: str) -> str:
    for block in re.split(r"\n\s*\n", md):
        b = block.strip()
        if b and not b.startswith(("#", "|", "```", "<", "-", ">", "1.")):
            text = _plain(b)
            return text if len(text) <= 160 else text[:157].rsplit(" ", 1)[0] + "…"
    return ""


def _slug(value: str, separator: str = "-") -> str:
    """GitHub-style heading ids, so #anchors work the same on GitHub and on the site."""
    value = html.unescape(re.sub(r"<[^>]+>", "", value)).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value)
    return value.replace(" ", separator)


def _lastmod(path: Path) -> str:
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", str(path)], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        out = ""
    return out or time.strftime("%Y-%m-%d")


def _rewrite(body: str, page: Page, by_path: dict[str, Page]) -> str:
    """Point relative links and images at the site (published pages, images) or GitHub."""
    here = PurePosixPath(page.repo_path).parent

    def target(url: str, image: bool) -> str:
        parts = urlsplit(url)
        if parts.scheme or parts.netloc or url.startswith(("#", "mailto:", "/")):
            return url
        resolved = _normalise(here / parts.path)
        frag = f"#{parts.fragment}" if parts.fragment else ""
        if resolved.startswith("docs/images/"):
            return "/images/" + resolved[len("docs/images/"):]
        if resolved in by_path:
            return by_path[resolved].url + frag
        kind = "raw/main" if image else ("tree/main" if not PurePosixPath(resolved).suffix else "blob/main")
        return f"{REPO}/{kind}/{resolved}{frag}"

    body = re.sub(r'(href)="([^"]+)"', lambda m: f'{m.group(1)}="{html.escape(target(html.unescape(m.group(2)), False))}"', body)
    body = re.sub(r'(src)="([^"]+)"', lambda m: f'{m.group(1)}="{html.escape(target(html.unescape(m.group(2)), True))}"', body)
    body = re.sub(r'srcset="([^"]+)"', lambda m: 'srcset="' + ", ".join(
        " ".join([target(p.split()[0], True), *p.split()[1:]]) for p in m.group(1).split(",")) + '"', body)
    return body


def _normalise(p: PurePosixPath) -> str:
    out: list[str] = []
    for part in p.parts:
        if part == "..":
            if out:
                out.pop()
        elif part not in (".", ""):
            out.append(part)
    return "/".join(out)


HEAD = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <meta name="description" content="{description}">
  <link rel="canonical" href="{canonical}">
  <meta property="og:type" content="article">
  <meta property="og:title" content="{title}">
  <meta property="og:description" content="{description}">
  <meta property="og:url" content="{canonical}">
  <meta property="og:image" content="{base}/images/02-compare-dark.png">
  <meta name="color-scheme" content="light dark">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><rect x='1' y='3' width='6' height='10' rx='1' fill='%234f6bed'/><rect x='9' y='3' width='6' height='10' rx='1' fill='%23e0864a'/></svg>">
  <link rel="stylesheet" href="/site.css">
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="top">
    <div class="wrap top-row">
      <a class="brand" href="/"><span class="mark" aria-hidden="true"><i></i><i></i></span>Lockstep</a>
      <nav aria-label="Main">
        <a href="/docs/">Docs</a>
        <a href="/#install">Install</a>
        <a href="{repo}">GitHub</a>
        <a class="btn small" href="https://demo.getlockstep.cloud">Try the demo</a>
      </nav>
    </div>
  </header>
"""

FOOT = """
  <footer class="foot">
    <div class="wrap">
      <p><a class="brand small" href="/"><span class="mark" aria-hidden="true"><i></i><i></i></span>Lockstep</a> is open source under the <a href="{repo}/blob/main/LICENSE">MIT licence</a>. <a href="{repo}">GitHub</a> · <a href="{repo}/releases">Releases</a> · <a href="/docs/">Docs</a> · <a href="{repo}/blob/main/SECURITY.md">Security</a></p>
      <p class="fine">Lockstep is an independent project. It is not affiliated with, endorsed by or sponsored by HashiCorp. HashiCorp and Vault are trademarks of HashiCorp, Inc.</p>
    </div>
  </footer>
</body>
</html>
"""


def _nav(pages: list[Page], current: Page | None) -> str:
    def items(section: str) -> str:
        return "\n".join(
            f'        <li><a href="{p.url}"{" aria-current=\"page\"" if p is current else ""}>{html.escape(p.title)}</a></li>'
            for p in pages if p.section == section)
    return f"""    <nav class="doc-nav" aria-label="Documentation">
      <h2>Guides</h2>
      <ul>
{items("guides")}
      </ul>
      <h2>Documentation</h2>
      <ul>
{items("docs")}
      </ul>
    </nav>"""


def render(page: Page, pages: list[Page], by_path: dict[str, Page]) -> str:
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                           extension_configs={"toc": {"slugify": _slug, "permalink": False}})
    source = re.sub(r"<!--\s*description:.*?-->\n?", "", page.text, count=1, flags=re.S)
    body = _rewrite(md.convert(source), page, by_path)
    edit = f"{REPO}/blob/main/{page.repo_path}"
    title = page.title if page.section == "guides" else f"{page.title} · Lockstep docs"
    return (HEAD.format(title=html.escape(title), description=html.escape(page.description, quote=True),
                        canonical=BASE + page.url, base=BASE, repo=REPO)
            + f"""  <main id="main" class="wrap doc-layout">
    <article class="doc">
{body}
      <p class="doc-edit"><a href="{edit}">View or edit this page on GitHub</a></p>
    </article>
{_nav(pages, page)}
  </main>"""
            + FOOT.format(repo=REPO))


def render_index(pages: list[Page]) -> str:
    def cards(section: str) -> str:
        return "\n".join(f"""        <article><h3><a href="{p.url}">{html.escape(p.title)}</a></h3>
          <p>{html.escape(p.description)}</p></article>""" for p in pages if p.section == section)
    desc = "Guides and documentation for Lockstep: compare and sync KV v2 secrets across HashiCorp Vault clusters."
    return (HEAD.format(title="Lockstep documentation and guides", description=desc, canonical=BASE + "/docs/",
                        base=BASE, repo=REPO)
            + f"""  <main id="main" class="wrap doc-index">
    <h1>Documentation</h1>
    <h2>Guides</h2>
    <div class="grid">
{cards("guides")}
    </div>
    <h2>Reference</h2>
    <div class="grid">
{cards("docs")}
    </div>
  </main>"""
            + FOOT.format(repo=REPO))


def main() -> int:
    pages = [Page(ROOT / f"docs/{name}.md", f"/docs/{name}/", "docs") for name in DOCS]
    found = {g.stem: g for g in (ROOT / "docs/guides").glob("*.md")}
    guides = [found.pop(n) for n in GUIDES if n in found] + sorted(found.values())
    pages = [Page(g, f"/guides/{g.stem}/", "guides") for g in guides] + pages
    by_path = {p.repo_path: p for p in pages}

    for d in ("docs", "guides"):
        for old in (SITE / d).glob("*/index.html"):
            old.unlink()
    for p in pages:
        out = SITE / p.url.strip("/") / "index.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render(p, pages, by_path))
    (SITE / "docs/index.html").write_text(render_index(pages))
    # JSON Schemas referenced by files Lockstep writes (the CLI report's first line)
    (SITE / "schemas").mkdir(exist_ok=True)
    for f in (ROOT / "schemas").glob("*.json"):
        (SITE / "schemas" / f.name).write_bytes(f.read_bytes())

    urls = [(BASE + "/", _lastmod(SITE / "index.html"), "1.0"), (BASE + "/docs/", _lastmod(ROOT / "docs"), "0.6")]
    urls += [(BASE + p.url, _lastmod(p.src), "0.8" if p.section == "guides" else "0.6") for p in pages]
    (SITE / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join(f"  <url><loc>{u}</loc><lastmod>{m}</lastmod><priority>{pr}</priority></url>\n"
                  for u, m, pr in urls)
        + "</urlset>\n")
    print(f"built {len(pages)} pages and sitemap.xml ({len(urls)} URLs) in {SITE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
