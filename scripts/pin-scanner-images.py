#!/usr/bin/env python3
"""Pin the scanner images in scan/versions.env to their tag's multi-arch index digest.

    python3 scripts/pin-scanner-images.py           # update the pins in place
    python3 scripts/pin-scanner-images.py --check   # exit 1 if any pin isn't a usable multi-arch index

Digests come straight from the registries, never from a local `podman/docker inspect`:
a local engine can report the digest of the platform-specific manifest it pulled
(e.g. arm64 on a Mac), and that pin then breaks on an amd64 CI runner with
"exec format error". Every pin must be an index with linux/amd64 and linux/arm64.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSIONS = Path(__file__).resolve().parent.parent / "scan" / "versions.env"
REQUIRED = {"linux/amd64", "linux/arm64"}
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
PIN_RE = re.compile(r"^(?P<var>[A-Z_]+_IMG)=(?P<name>[^@\s]+)@(?P<digest>sha256:[0-9a-f]{64})$", re.M)


def _split(name: str) -> tuple[str, str, str]:
    registry, rest = name.split("/", 1)
    repo, tag = rest.rsplit(":", 1) if ":" in rest else (rest, "latest")
    if registry == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    return registry, repo, tag


def _open(req, timeout: int = 30, attempts: int = 4):
    """urlopen with retries: CI runners occasionally hit transient DNS/network errors."""
    for i in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError:
            raise  # a real answer from the registry: don't retry
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if i == attempts - 1:
                raise
            wait = 2 ** i * 2
            print(f"   network error ({e}); retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)


def _token(registry: str, repo: str) -> str | None:
    urls = {
        "docker.io": f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull",
        "ghcr.io": f"https://ghcr.io/token?scope=repository:{repo}:pull",
    }
    if registry not in urls:
        return None  # e.g. registry.access.redhat.com allows anonymous pulls
    with _open(urls[registry], timeout=20) as r:
        return json.load(r)["token"]


def manifest(registry: str, repo: str, ref: str) -> tuple[str, dict]:
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    headers = {"Accept": ACCEPT}
    if tok := _token(registry, repo):
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(f"https://{host}/v2/{repo}/manifests/{ref}", headers=headers)
    with _open(req) as r:
        return r.headers["Docker-Content-Digest"], json.load(r)


def platforms(m: dict) -> set[str]:
    return {f"{x['platform']['os']}/{x['platform']['architecture']}"
            for x in m.get("manifests", []) if "platform" in x}


BASE_FILES = ["Dockerfile", "dev/seed/Dockerfile", "dev/e2e/Dockerfile", "dev/dex/Dockerfile", "compose.yaml", "deploy/demo/compose.yaml"]
REF_RE = re.compile(r"(?P<name>(?:registry\.access\.redhat\.com|docker\.io|ghcr\.io|quay\.io|mcr\.microsoft\.com)/[a-z0-9./_-]+(?::[A-Za-z0-9._-]+)?)@(?P<digest>sha256:[0-9a-f]{64})")


def check_base_images() -> bool:
    """Base images pinned in Dockerfiles/compose must also be multi-arch indexes."""
    ok = True
    root = VERSIONS.parent.parent
    refs = sorted({(m["name"], m["digest"]) for f in BASE_FILES for m in REF_RE.finditer((root / f).read_text())})
    for name, digest in refs:
        registry, repo, _ = _split(name)
        _, pm = manifest(registry, repo, digest)
        plats = platforms(pm)
        good = REQUIRED <= plats
        ok &= good
        print(f"{'ok ' if good else 'BAD'} base: {name}@{digest[7:19]} "
              f"{'index ' + ','.join(sorted(plats)) if plats else 'single-arch manifest'}")
    return ok


def main() -> int:
    check = "--check" in sys.argv
    text = VERSIONS.read_text()
    ok = check_base_images() if check else True
    for m in PIN_RE.finditer(text):
        var, name, pinned = m["var"], m["name"], m["digest"]
        registry, repo, tag = _split(name)
        if check:
            _, pm = manifest(registry, repo, pinned)
            plats = platforms(pm)
            good = REQUIRED <= plats
            ok &= good
            print(f"{'ok ' if good else 'BAD'} {var}: {name}@{pinned[7:19]} "
                  f"{'index ' + ','.join(sorted(plats)) if plats else 'single-arch manifest'}")
            continue
        digest, im = manifest(registry, repo, tag)
        plats = platforms(im)
        if not REQUIRED <= plats:
            print(f"BAD {var}: {name} has no multi-arch index with {sorted(REQUIRED)} (got {sorted(plats) or 'single manifest'})")
            ok = False
            continue
        if digest != pinned:
            text = text.replace(f"{name}@{pinned}", f"{name}@{digest}")
            print(f"->  {var}: {name} {pinned[7:19]} -> {digest[7:19]}  ({','.join(sorted(plats))})")
        else:
            print(f"    {var}: {name} up to date ({','.join(sorted(plats))})")
    if not check:
        VERSIONS.write_text(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
