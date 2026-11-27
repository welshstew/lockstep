"""Reading `vault kv get -format=json` output as an export, so it can be compared or imported.

`vault kv get` (and `vault read`) print one secret, without its path:

    {"request_id": "…", "lease_id": "", "lease_duration": 0, "renewable": false,
     "data": {"data": {"user": "app"}, "metadata": {"version": 3, "created_time": "…", …}},
     "warnings": null, "mount_type": "kv"}

KV v1 prints the keys directly under "data". Three shapes are read:

  - one file of that output: the secret's path is the file name without .json;
  - several files (a folder): each path is the file's path in the folder, without .json;
  - one JSON object of {"<path>": <that output>, …}, as a shell loop with jq writes it:

        for p in $(vault kv list -format=json secret/app | jq -r '.[]'); do
          vault kv get -format=json "secret/app/$p" | jq --arg p "$p" '{($p): .}'
        done | jq -s add > app.json

A secret whose latest version is deleted or destroyed has no data: it's listed as skipped.
Pure: nothing here talks to Vault.
"""

from __future__ import annotations

import time
from typing import Any

from .exports import ExportDoc, ExportError, ExportSecret, ExportSkipped, ExportSource

_ENVELOPE = ("request_id", "lease_id", "lease_duration", "renewable", "warnings", "mount_type", "wrap_info")
MAX_FILES = 10000


def is_kv_get(obj: Any) -> bool:
    """Whether this is `vault kv get -format=json` (or `vault read`) output."""
    return isinstance(obj, dict) and "data" in obj and any(k in obj for k in _ENVELOPE)


def is_kv_get_map(obj: Any) -> bool:
    return isinstance(obj, dict) and bool(obj) and all(is_kv_get(v) for v in obj.values())


def _path(text: str, strip_json: bool) -> str:
    p = text.replace("\\", "/").strip().strip("/")
    if strip_json and p.lower().endswith(".json"):
        p = p[:-5]
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if not parts or ".." in parts:
        raise ExportError(f"{text!r} can't be a secret path.")
    return "/".join(parts)


def _secret(path: str, out: Any) -> tuple[ExportSecret | None, str | None]:
    """The secret, or (None, path) when its latest version is deleted or destroyed."""
    data = out.get("data")
    if isinstance(data, dict) and set(data) <= {"data", "metadata"} and "metadata" in data:  # KV v2
        meta = data.get("metadata") or {}
        values = data.get("data")
        if values is None or meta.get("deletion_time") or meta.get("destroyed"):
            return None, path
        version = meta.get("version") if isinstance(meta.get("version"), int) else None
        updated = meta.get("created_time") if isinstance(meta.get("created_time"), str) else None
    else:  # KV v1, or `vault read`
        values, version, updated = data, None, None
    if not isinstance(values, dict):
        raise ExportError(f"{path}: the output's data isn't an object of keys and values.")
    return ExportSecret(path=path, version=version, updated=updated, data=values), None


def convert(files: list[tuple[str, Any]], name: str, tool: str = "lockstep") -> ExportDoc:
    """An export from `vault kv get -format=json` output: (file name or path in a folder, parsed JSON)."""
    if not files:
        raise ExportError("No files to read.")
    if len(files) > MAX_FILES:
        raise ExportError(f"At most {MAX_FILES} files.")
    items: list[tuple[str, Any]] = []
    for fname, obj in files:
        if is_kv_get(obj):
            items.append((_path(fname, strip_json=True), obj))
        elif is_kv_get_map(obj):
            if len(obj) > MAX_FILES:
                raise ExportError(f"At most {MAX_FILES} secrets.")
            items += [(_path(k, strip_json=False), v) for k, v in obj.items()]
        else:
            raise ExportError(f"{fname} isn't a Lockstep export or `vault kv get -format=json` output "
                              "(one secret, or an object of path: output).")
    secrets: list[ExportSecret] = []
    deleted: list[str] = []
    seen: set[str] = set()
    for path, out in items:
        if path in seen:
            raise ExportError(f"{path} appears twice.")
        seen.add(path)
        secret, gone = _secret(path, out)
        if secret:
            secrets.append(secret)
        else:
            deleted.append(gone)
    return ExportDoc(created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), tool=f"{tool}, from vault kv get",
                     source=ExportSource(vault=name, mount="vault kv get"),
                     secrets=sorted(secrets, key=lambda s: s.path),
                     skipped=ExportSkipped(deleted=sorted(deleted)))
