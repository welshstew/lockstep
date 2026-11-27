"""Streamed exports: the document is written as secrets are read, never held whole."""

import asyncio
import json
import logging
import tracemalloc

from lockstep import exports as ex
from lockstep.vault import KvSecret, TreeResult, VaultError
from test_exports import env  # noqa: F401  (fixture)


class FakeVault:
    """A KV mount of `n` secrets with ~1 KB of values each, made up on demand."""

    def __init__(self, n: int, unreadable: set[str] = frozenset()):
        self.n, self.unreadable = n, unreadable

    async def kv_tree(self, mount, prefix, max_secrets=5000):
        return TreeResult(secrets=[f"{prefix}s{i:06d}" for i in range(self.n)], denied=[f"{prefix}hidden/"])

    async def kv_read(self, mount, path):
        if path in self.unreadable:
            raise VaultError(403, "permission denied")
        i = int(path.rsplit("s", 1)[1])
        return KvSecret(state="present", data={"user": f"u{i}", "blob": f"{i:08d}" * 128}, version=1,
                        updated="2026-11-01T00:00:00Z")


SOURCE = ex.ExportSource(vault="Fake", mount="kv")


def test_stream_matches_build_and_seals():
    v = FakeVault(300, unreadable={"app/s000007"})
    doc = asyncio.run(ex.build(v, mount="kv", prefix="app", rules=None, source=SOURCE))
    assert len(doc.secrets) == 299 and doc.skipped.unreadable == ["s000007"] and doc.skipped.denied_folders == ["hidden/"]
    assert [s.path for s in doc.secrets] == sorted(s.path for s in doc.secrets)

    packer, seen = ex.Packer(), []

    async def progress(done, total):
        seen.append((done, total))

    built = asyncio.run(ex.stream(v, mount="kv", prefix="app", rules=None, source=SOURCE, write=packer.write,
                                  progress=progress, window=64))
    assert (built.secrets, built.keys) == (299, 598) and seen[-1] == (300, 300) and len(seen) == 5
    env_, key = ex.seal_key(packer.done(built))
    assert env_.source.secrets == 299
    opened = ex.load(env_.dump(), key)
    assert opened.secrets == doc.secrets and opened.skipped == doc.skipped


def test_streaming_holds_far_less_than_building():
    """20,000 secrets (~20 MB of JSON): building holds the whole document; streaming into the
    packer holds only the compressed bytes."""
    v = FakeVault(20000)

    async def built_whole():
        doc = await ex.build(v, mount="kv", prefix="", rules=None, source=SOURCE)
        return ex.pack(doc)

    async def streamed():
        packer = ex.Packer()
        built = await ex.stream(v, mount="kv", prefix="", rules=None, source=SOURCE, write=packer.write)
        return packer.done(built)

    peaks = []
    for fn in (built_whole, streamed):
        tracemalloc.start()
        asyncio.run(fn())
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    whole, stream = peaks
    assert stream * 5 < whole, (whole, stream)


def _lines(r):
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def test_api_stream(env, client, caplog):  # noqa: F811
    for i in range(70):
        env.a.put(f"{env.prefix}/s{i:02d}", {"k": f"v{i}"})
    side = env.side_a
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        plain = client.post("/api/exports/stream", json={"side": side, "encrypt": False})
    assert plain.status_code == 200 and plain.headers["content-type"].startswith("application/x-ndjson")
    lines = _lines(plain)
    assert len(lines) == 1  # a plain export streams inside its result line
    res = lines[0]["result"]
    assert res["scheme"] == "none" and res["key"] is None and res["secrets"] == 70 and res["keys"] == 70
    assert res["filename"].startswith("lockstep-export-Vault_A-app-config-") and not res["filename"].endswith(".encrypted.json")
    assert ex.load(res["file"]).secrets[0].data == {"k": "v0"}
    entry = json.loads([r.message for r in caplog.records if '"event": "export"' in r.message][-1])
    assert entry["outcome"] == "created" and entry["secrets"] == 70 and entry["scheme"] == "none"

    enc = _lines(client.post("/api/exports/stream", json={"side": side}))
    assert [ln["progress"] for ln in enc[:-1]] == [{"done": 64, "total": 70}, {"done": 70, "total": 70}]
    res = enc[-1]["result"]
    assert res["scheme"] == "key" and res["key"].startswith("lsk1.") and res["file"]["source"]["secrets"] == 70
    assert len(ex.load(res["file"], res["key"]).secrets) == 70

    r = client.post("/api/exports/stream", json={"side": side, "passphrase": "short"})
    assert r.status_code == 400 and "at least 12" in r.text  # checked before the stream starts
    r = client.post("/api/exports/stream", json={"side": env.side_b, "encrypt": False})
    assert r.status_code == 403  # Vault B allows encrypted exports only
