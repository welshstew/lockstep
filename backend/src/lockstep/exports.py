"""Secret-engine exports: the file format, encryption, import rules and transforms.

Used by the web API (api/exports.py) and the CLI. Only `build` talks to Vault, through the
client it's given; everything else is pure.

An export is a JSON document (`lockstep.secret-export`, version 1): where it came from, the
rules it was made with, and every secret's data with its version. It holds secret values, so
it is normally encrypted:

    lockstep.secret-export.encrypted   one of three schemes:
      key         (version 1) AES-256-GCM with a random 256-bit one-time key, zlib-compressed.
                  The key is shown to the user once ("lsk1." + base64url) and never stored.
      passphrase  (version 2) the same, with the key derived from a passphrase by Argon2id;
                  the salt and cost are in the header.
      age         (version 2) an armored age file (age-encryption.org) of the plain export,
                  for the age public keys in `recipients`: `age -d` opens it without Lockstep.

The envelope's small header (vault name, mount, prefix, secret count, time) is readable,
so people can tell files apart. With a key or a passphrase it is bound to the ciphertext as
associated data, so it can't be altered without the key noticing. age has no associated
data, so the decrypted export must match the header instead.

Import rules are applied to an export before it's compared or written: ignore paths and
keys first (globs over the exported paths), then transforms in order.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import fnmatch
import io
import json
import os
import re
import time
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import pyrage
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from pyrage import x25519
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .rules import IgnoreKey, compile_glob
from .vault import KvSecret, TreeResult, VaultError

FORMAT = "lockstep.secret-export"
ENCRYPTED_FORMAT = "lockstep.secret-export.encrypted"
SCHEMA_URL = "https://getlockstep.cloud/schemas/lockstep-export-v1.json"
RULES_SCHEMA_URL = "https://getlockstep.cloud/schemas/lockstep-import-rules-v1.json"
KEY_PREFIX = "lsk1."
MAX_TRANSFORMS = 50
# Argon2id for passphrases: RFC 9106's second recommendation (64 MiB, 3 passes, 4 lanes). A file
# may ask for more, up to these limits, so a crafted file can't make the server use a lot of memory.
KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_LANES = 64 * 1024, 3, 4
MAX_KDF_MEMORY_KIB = 256 * 1024
MIN_PASSPHRASE = 12
MAX_RECIPIENTS = 50


class ExportError(ValueError):
    """The file isn't a usable export (wrong format, wrong key, damaged…). Message is user-facing."""


# --------------------------------------------------------------------------- the document


class ExportSource(BaseModel):
    vault: str = Field(description="The connection's name when exported")
    url: str | None = Field(default=None, description="The Vault address (left out for preset connections)")
    namespace: str | None = None
    mount: str
    prefix: str = Field(default="", description="Paths below are relative to this prefix")
    identity: str = Field(default="", description="Who exported it, as Vault reported them")


class ExportRules(BaseModel):
    """What was left out when exporting."""

    ignore_paths: list[str] = Field(default_factory=list, max_length=200)
    ignore_keys: list[IgnoreKey] = Field(default_factory=list, max_length=200)


class ExportSecret(BaseModel):
    """A secret with its data, or a keep entry: a path with "keep": true and no data."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"oneOf": [
        {"required": ["data"], "properties": {"keep": {"const": False}}},
        {"required": ["keep"], "properties": {"keep": {"const": True}, "data": {"maxProperties": 0}}}]})

    path: str = Field(min_length=1, description="Relative to source.prefix")
    version: int | None = None
    updated: str | None = None
    data: dict[str, Any] | None = Field(default=None, description="The secret's keys and values (not with keep)")
    keep: bool = Field(default=False, description=(
        "Leave the target's secret at this path as it is, with no data: it's neither written nor "
        "deleted, even when an import deletes what isn't in the file"))

    @model_validator(mode="after")
    def _data_or_keep(self):
        if self.keep and self.data:
            raise ValueError(f"{self.path}: a keep entry has no data")
        if not self.keep and self.data is None:
            raise ValueError(f"{self.path}: data is required (or keep: true)")
        return self


class ExportSkipped(BaseModel):
    ignored_paths: int = 0
    ignored_keys: int = 0
    unreadable: list[str] = Field(default_factory=list, description="Secrets that couldn't be read")
    deleted: list[str] = Field(default_factory=list, description="Secrets whose latest version is deleted")
    denied_folders: list[str] = Field(default_factory=list, description="Folders that couldn't be listed")
    truncated: bool = Field(default=False, description="True if the listing hit the size limit")


class ExportDoc(BaseModel):
    """A secret-engine export with values. Treat it like the secrets themselves."""

    model_config = ConfigDict(title="Lockstep secret-engine export", extra="forbid")

    schema_: str | None = Field(default=SCHEMA_URL, alias="$schema")
    format: Literal["lockstep.secret-export"] = FORMAT
    version: Literal[1] = 1
    created_at: str
    tool: str = ""
    source: ExportSource
    rules: ExportRules = Field(default_factory=ExportRules)
    secrets: list[ExportSecret]
    skipped: ExportSkipped = Field(default_factory=ExportSkipped)

    @field_validator("secrets")
    @classmethod
    def _unique(cls, v: list[ExportSecret]) -> list[ExportSecret]:
        seen: set[str] = set()
        for s in v:
            if s.path in seen:
                raise ValueError(f"duplicate path {s.path}")
            seen.add(s.path)
        return v

    def dump(self) -> dict:
        out = self.model_dump(mode="json", by_alias=True)
        for s in out["secrets"]:  # only keep entries say keep (and they have no data)
            if s["keep"]:
                s.pop("data", None)
            else:
                s.pop("keep")
        return out


class EncryptedSource(BaseModel):
    vault: str
    mount: str
    prefix: str = ""
    secrets: int


class Kdf(BaseModel):
    """How a passphrase becomes the key (RFC 9106 Argon2id)."""

    model_config = ConfigDict(extra="forbid")

    name: Literal["argon2id"] = "argon2id"
    salt: str = Field(description="base64, 16 bytes")
    memory_kib: int = Field(ge=8 * 1024, le=MAX_KDF_MEMORY_KIB)
    iterations: int = Field(ge=1, le=10)
    lanes: int = Field(ge=1, le=16)


class EncryptedExport(BaseModel):
    """An encrypted export: open it with the one-time key shown when it was made, the
    passphrase it was made with, or an age identity for one of its recipients."""

    model_config = ConfigDict(title="Lockstep secret-engine export (encrypted)", extra="forbid")

    schema_: str | None = Field(default=SCHEMA_URL, alias="$schema")
    format: Literal["lockstep.secret-export.encrypted"] = ENCRYPTED_FORMAT
    version: Literal[1, 2] = 1  # 1: a one-time key; 2: a passphrase or age
    created_at: str
    scheme: Literal["key", "passphrase", "age"] = "key"
    cipher: Literal["AES-256-GCM", "age"] = "AES-256-GCM"
    compression: Literal["zlib", "none"] = "zlib"
    kdf: Kdf | None = Field(default=None, description="scheme passphrase: how the key is derived")
    recipients: list[str] = Field(default_factory=list, description="scheme age: the age public keys it's for")
    source: EncryptedSource
    nonce: str = Field(default="", description="base64, 12 bytes (not used by age)")
    ciphertext: str = Field(description="base64: the zlib-compressed export, encrypted; for age, an armored age file "
                                         "of the plain export")

    @model_validator(mode="after")
    def _consistent(self):
        ok = {"key": (1, "AES-256-GCM", "zlib"), "passphrase": (2, "AES-256-GCM", "zlib"), "age": (2, "age", "none")}
        if (self.version, self.cipher, self.compression) != ok[self.scheme]:
            raise ValueError(f"version, cipher and compression don't fit the {self.scheme} scheme")
        if (self.kdf is not None) != (self.scheme == "passphrase") or bool(self.recipients) != (self.scheme == "age"):
            raise ValueError(f"kdf and recipients don't fit the {self.scheme} scheme")
        return self

    def header(self) -> bytes:
        """The associated data: everything except the nonce and ciphertext (and $schema). The
        version 1 header is exactly what it always was, so old files still open."""
        exclude = {"nonce", "ciphertext", "schema_"}
        if self.scheme == "key":
            exclude |= {"scheme", "kdf", "recipients"}
        h = self.model_dump(mode="json", exclude=exclude)
        return json.dumps(h, sort_keys=True, separators=(",", ":")).encode()

    def dump(self) -> dict:
        exclude = {"key": {"scheme", "kdf", "recipients"}, "passphrase": {"recipients"}, "age": {"nonce", "kdf"}}
        return self.model_dump(mode="json", by_alias=True, exclude=exclude[self.scheme])


def schema() -> dict:
    """The published JSON Schema: either form of the file."""
    plain = ExportDoc.model_json_schema(by_alias=True)
    enc = EncryptedExport.model_json_schema(by_alias=True)
    defs = {**plain.pop("$defs", {}), **enc.pop("$defs", {})}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_URL,
        "title": "Lockstep secret-engine export",
        "description": "A KV v2 secret engine exported by Lockstep, either as plain JSON with values or "
                       "encrypted with a one-time key, a passphrase or age public keys. Plain exports hold secret values.",
        "oneOf": [{"$ref": "#/$defs/ExportDoc"}, {"$ref": "#/$defs/EncryptedExport"}],
        "$defs": {**defs, "ExportDoc": plain, "EncryptedExport": enc},
    }


# --------------------------------------------------------------------------- encryption


def new_key() -> tuple[bytes, str]:
    raw = AESGCM.generate_key(bit_length=256)
    return raw, KEY_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_key(text: str) -> bytes:
    t = "".join(text.split())
    if not t.startswith(KEY_PREFIX):
        raise ExportError(f"That isn't an export key (they start with {KEY_PREFIX}).")
    body = t[len(KEY_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError) as e:
        raise ExportError("That export key is damaged.") from e
    if len(raw) != 32:
        raise ExportError("That export key is damaged (wrong length).")
    return raw


def _source(doc: ExportDoc) -> EncryptedSource:
    return EncryptedSource(vault=doc.source.vault, mount=doc.source.mount, prefix=doc.source.prefix,
                           secrets=len(doc.secrets))


def _plain(doc: ExportDoc) -> bytes:
    return json.dumps(doc.dump(), separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class Packed:
    """A plain export document, zlib-compressed, with what the readable header needs. Encrypting
    starts from this, so a streamed export only ever holds the compressed bytes."""
    data: bytes
    created_at: str
    source: EncryptedSource


def pack(doc: ExportDoc) -> Packed:
    return Packed(zlib.compress(_plain(doc), 9), doc.created_at, _source(doc))


class Packer:
    """Compresses an export as `stream` writes it."""

    def __init__(self) -> None:
        self._z = zlib.compressobj(9)
        self._out = bytearray()

    async def write(self, b: bytes) -> None:
        self._out += self._z.compress(b)

    def done(self, built: Built) -> Packed:
        self._out += self._z.flush()
        src = EncryptedSource(vault=built.source.vault, mount=built.source.mount, prefix=built.source.prefix,
                              secrets=built.secrets)
        return Packed(bytes(self._out), built.created_at, src)


def _seal(env: EncryptedExport, raw: bytes, packed: Packed) -> EncryptedExport:
    nonce = os.urandom(12)
    env.nonce = base64.b64encode(nonce).decode()
    env.ciphertext = base64.b64encode(AESGCM(raw).encrypt(nonce, packed.data, env.header())).decode()
    return env


def seal_key(packed: Packed) -> tuple[EncryptedExport, str]:
    """Encrypt with a fresh one-time key. Returns the envelope and the key text."""
    raw, text = new_key()
    env = EncryptedExport(created_at=packed.created_at, ciphertext="", source=packed.source)
    return _seal(env, raw, packed), text


def encrypt(doc: ExportDoc) -> tuple[EncryptedExport, str]:
    """Encrypt an export with a fresh one-time key. Returns the envelope and the key text."""
    return seal_key(pack(doc))


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise ExportError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
    if len(passphrase) > 1024:
        raise ExportError("That passphrase is too long (1024 characters at most).")


def _derive(passphrase: str, kdf: Kdf) -> bytes:
    try:
        salt = base64.b64decode(kdf.salt, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExportError("The file is damaged (invalid salt).") from e
    if len(salt) < 16:
        raise ExportError("The file is damaged (salt too short).")
    return Argon2id(salt=salt, length=32, iterations=kdf.iterations, lanes=kdf.lanes,
                    memory_cost=kdf.memory_kib).derive(passphrase.encode())


def seal_passphrase(packed: Packed, passphrase: str) -> EncryptedExport:
    """Encrypt with a key derived from a passphrase (Argon2id, then AES-256-GCM)."""
    check_passphrase(passphrase)
    kdf = Kdf(salt=base64.b64encode(os.urandom(16)).decode(), memory_kib=KDF_MEMORY_KIB,
              iterations=KDF_ITERATIONS, lanes=KDF_LANES)
    env = EncryptedExport(version=2, scheme="passphrase", kdf=kdf, created_at=packed.created_at, ciphertext="",
                          source=packed.source)
    return _seal(env, _derive(passphrase, kdf), packed)


def encrypt_passphrase(doc: ExportDoc, passphrase: str) -> EncryptedExport:
    return seal_passphrase(pack(doc), passphrase)


def parse_recipients(items: list[str]) -> list[str]:
    """age public keys (age1…), one per item or per line; `#` comments and blank lines are
    skipped, as in an age recipients file. Returns them normalised and without duplicates."""
    out: list[str] = []
    for item in items:
        for line in item.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                key = str(x25519.Recipient.from_str(line))
            except pyrage.RecipientError as e:
                shown = line if len(line) <= 70 else line[:67] + "…"
                raise ExportError(f"{shown} isn't an age public key (they start with age1): {e}.") from e
            if key not in out:
                out.append(key)
    if not out:
        raise ExportError("Give at least one age public key.")
    if len(out) > MAX_RECIPIENTS:
        raise ExportError(f"At most {MAX_RECIPIENTS} age public keys.")
    return out


class _Inflate(io.RawIOBase):
    """Reads a Packed export's plain bytes, decompressing as it goes."""

    def __init__(self, data: bytes) -> None:
        self._z = zlib.decompressobj()
        self._src = memoryview(data)
        self._pos = 0
        self._pending = b""

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._pending:
            if self._z.unconsumed_tail:
                self._pending = self._z.decompress(self._z.unconsumed_tail, 1 << 16)
            elif self._pos < len(self._src):
                chunk = self._src[self._pos:self._pos + (1 << 16)]
                self._pos += len(chunk)
                self._pending = self._z.decompress(chunk, 1 << 16)
            else:
                self._pending = self._z.flush()
                if not self._pending:
                    return 0
        n = min(len(b), len(self._pending))
        b[:n] = self._pending[:n]
        self._pending = self._pending[n:]
        return n


def seal_age(packed: Packed, recipients: list[str]) -> EncryptedExport:
    """Encrypt to age public keys: the ciphertext is an armored age file of the plain export, so
    `age -d -i key.txt` opens it too. The plain bytes are decompressed as age reads them."""
    keys = parse_recipients(recipients)
    out = io.BytesIO()
    try:
        pyrage.encrypt_io(io.BufferedReader(_Inflate(packed.data)), out,
                          [x25519.Recipient.from_str(k) for k in keys], armored=True)
    except pyrage.EncryptError as e:
        raise ExportError(f"Couldn't encrypt to those keys: {e}") from e
    return EncryptedExport(version=2, scheme="age", cipher="age", compression="none", recipients=keys,
                           created_at=packed.created_at, ciphertext=out.getvalue().decode(), source=packed.source)


def encrypt_age(doc: ExportDoc, recipients: list[str]) -> EncryptedExport:
    return seal_age(pack(doc), recipients)


MAX_PLAINTEXT = 256 * 1024 * 1024  # decompression limit (a zip bomb guard)


def _identities(text: str) -> list:
    """age identities from pasted text or an identity file (AGE-SECRET-KEY-1… lines)."""
    found = [line.strip() for line in text.splitlines() if line.strip().upper().startswith("AGE-SECRET-KEY-1")]
    if not found:
        raise ExportError("That isn't an age identity: paste the AGE-SECRET-KEY-1… line from your key file.")
    try:
        return [x25519.Identity.from_str(line) for line in found]
    except pyrage.IdentityError as e:
        raise ExportError(f"That age identity is damaged: {e}.") from e


def _decrypt_age(env: EncryptedExport, identity_text: str) -> ExportDoc:
    try:
        plain = pyrage.decrypt(env.ciphertext.encode(), _identities(identity_text))
    except pyrage.DecryptError as e:
        raise ExportError("This file isn't encrypted to that age key, or it was changed or damaged.") from e
    if len(plain) > MAX_PLAINTEXT:
        raise ExportError("The export is too large to open.")
    try:
        doc = ExportDoc.model_validate_json(plain)
    except ValidationError as e:
        raise ExportError(f"The decrypted export isn't valid: {e.errors()[0]['msg']}") from e
    # age can't authenticate the readable header, so it has to agree with what's inside
    if _source(doc) != env.source or doc.created_at != env.created_at:
        raise ExportError("The file's readable header doesn't match its contents: it was changed. Don't trust it.")
    return doc


def decrypt(env: EncryptedExport, key_text: str) -> ExportDoc:
    if env.scheme == "age":
        return _decrypt_age(env, key_text)
    raw = _derive(key_text, env.kdf) if env.scheme == "passphrase" else parse_key(key_text)
    try:
        nonce, ct = base64.b64decode(env.nonce, validate=True), base64.b64decode(env.ciphertext, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExportError("The file is damaged (invalid base64).") from e
    try:
        packed = AESGCM(raw).decrypt(nonce, ct, env.header())
    except (InvalidTag, ValueError) as e:
        what = "passphrase" if env.scheme == "passphrase" else "key"
        raise ExportError(f"Wrong {what}, or the file was changed or damaged.") from e
    d = zlib.decompressobj()
    plain = d.decompress(packed, MAX_PLAINTEXT)
    if d.unconsumed_tail:
        raise ExportError("The export is too large to open.")
    try:
        return ExportDoc.model_validate_json(plain)
    except ValidationError as e:
        raise ExportError(f"The decrypted export isn't valid: {e.errors()[0]['msg']}") from e


def load(obj: Any, key: str | None = None) -> ExportDoc:
    """An export document from a parsed file: plain, or encrypted (needs `key`)."""
    if not isinstance(obj, dict) or obj.get("format") not in (FORMAT, ENCRYPTED_FORMAT):
        raise ExportError("That isn't a Lockstep export file.")
    if obj.get("version") not in ((1,) if obj["format"] == FORMAT else (1, 2)):
        raise ExportError(f"Unsupported export version {obj.get('version')!r}: update Lockstep.")
    try:
        if obj["format"] == FORMAT:
            return ExportDoc.model_validate(obj)
        env = EncryptedExport.model_validate(obj)
    except ValidationError as e:
        err = e.errors()[0]
        raise ExportError(f"The export file isn't valid ({'.'.join(map(str, err['loc']))}: {err['msg']}).") from e
    if not key:
        raise ExportError({"key": "This export is encrypted: enter its key.",
                           "passphrase": "This export is encrypted with a passphrase: enter it.",
                           "age": "This export is encrypted to age keys: paste your age identity."}[env.scheme])
    return decrypt(env, key)


# --------------------------------------------------------------------------- building an export


@dataclass
class Built:
    """What an export holds, known once `stream` has written it."""
    created_at: str
    source: ExportSource
    secrets: int
    keys: int
    skipped: ExportSkipped


Write = Callable[[bytes], Awaitable[None]]
Progress = Callable[[int, int], Awaitable[None]]


async def stream(v, *, mount: str, prefix: str, rules: ExportRules | None, source: ExportSource, write: Write,
                 max_secrets: int = 5000, tool: str = "", tree: TreeResult | None = None,
                 progress: Progress | None = None, window: int = 64, concurrency: int = 16) -> Built:
    """Read every secret under mount/prefix (current versions) and write the export document's
    JSON as it goes, in path order, holding at most `window` secrets at a time. `v` is a
    VaultClient; `tree`, if given, is its listing (so listing errors can be reported first).
    Leaves out what `rules` ignores. Listing errors other than "permission denied" raise
    VaultError; unreadable secrets and folders are recorded in `skipped`."""
    rules = rules or ExportRules()
    base = _norm(prefix)
    full = f"{base}/" if base else ""
    if tree is None:
        tree = await v.kv_tree(mount, full, max_secrets=max_secrets)
    ign_paths = [compile_glob(_norm(p)) for p in rules.ignore_paths if p.strip()]
    ign_keys = [(compile_glob(_norm(k.path) or "**"), k.key) for k in rules.ignore_keys]
    skipped = ExportSkipped(denied_folders=[d[len(full):] for d in tree.denied], truncated=tree.truncated)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    source = source.model_copy(update={"mount": mount, "prefix": base})

    head = ExportDoc(created_at=created, tool=tool, source=source, rules=rules, secrets=[]).dump()
    del head["secrets"], head["skipped"]
    await write(_compact(head)[:-1] + b',"secrets":[')

    sem = asyncio.Semaphore(concurrency)

    async def one(path: str):
        rel = path[len(full):]
        if any(rx.match(rel) for rx in ign_paths):
            return rel, "ignored", None
        try:
            async with sem:
                s = await v.kv_read(mount, path)
        except VaultError:
            return rel, "unreadable", None
        if s.state != "present":
            return rel, s.state, None
        data = {}
        for k, val in (s.data or {}).items():
            if any(prx.match(rel) and fnmatch.fnmatchcase(k, kg) for prx, kg in ign_keys):
                skipped.ignored_keys += 1
            else:
                data[k] = val
        return rel, "ok", ExportSecret(path=rel, version=s.version, updated=s.updated, data=data)

    paths = sorted(tree.secrets)
    written = n_keys = 0
    for i in range(0, len(paths), window):
        for rel, state, secret in await asyncio.gather(*(one(p) for p in paths[i:i + window])):
            if state == "ok" and secret.data:
                await write((b"," if written else b"") + _compact(secret.model_dump(mode="json")))
                written += 1
                n_keys += len(secret.data)
            elif state in ("ok", "ignored"):
                skipped.ignored_paths += 1  # an ignored path, or every key ignored
            elif state == "deleted":
                skipped.deleted.append(rel)
            elif state == "unreadable":
                skipped.unreadable.append(rel)
        if progress:
            await progress(min(i + window, len(paths)), len(paths))
    await write(b'],"skipped":' + _compact(skipped.model_dump(mode="json")) + b"}")
    return Built(created_at=created, source=source, secrets=written, keys=n_keys, skipped=skipped)


def _compact(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


async def build(v, *, mount: str, prefix: str, rules: ExportRules | None, source: ExportSource,
                max_secrets: int = 5000, tool: str = "") -> ExportDoc:
    """The whole export as a document in memory (`stream` writes it without holding it)."""
    buf = bytearray()

    async def write(b: bytes) -> None:
        buf.extend(b)

    await stream(v, mount=mount, prefix=prefix, rules=rules, source=source, write=write,
                 max_secrets=max_secrets, tool=tool)
    return ExportDoc.model_validate_json(bytes(buf))


def file_name(doc: ExportDoc | Built, encrypted: bool) -> str:
    """A descriptive file name: lockstep-export-<vault>-<mount>[-<prefix>]-<time>[.encrypted].json"""
    parts = [doc.source.vault, doc.source.mount, doc.source.prefix]
    slug = "-".join(re.sub(r"[^A-Za-z0-9._-]+", "_", p).strip("._-") for p in parts if p)
    stamp = doc.created_at.replace("-", "").replace(":", "")[:13]  # 20261110T1830
    return f"lockstep-export-{slug}-{stamp}{'.encrypted' if encrypted else ''}.json"


# --------------------------------------------------------------------------- import rules and transforms


class Transform(BaseModel):
    """One change applied to an export before it's compared or imported."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    op: Literal["replace", "prefix", "suffix", "upper", "lower"] = Field(
        description="replace: every occurrence of `find` with `with`; prefix/suffix: add `with` before/after; "
                    "upper/lower: change case")
    target: Literal["values", "keys", "paths"] = Field(
        default="values", description="What to change: string values, key names, or secret paths")
    find: str = Field(default="", max_length=1000, description="replace: the text to find (case-sensitive)")
    with_: str = Field(default="", alias="with", max_length=1000, description="replace/prefix/suffix: the new text")
    path: str = Field(default="**", max_length=512, description="Only secrets whose path matches this glob")
    key: str = Field(default="*", max_length=256, description="Only keys matching this pattern (values and keys)")

    @model_validator(mode="after")
    def _needs_find(self):
        if self.op == "replace" and not self.find:
            raise ValueError("a replace transform needs text to find")
        return self

    def apply(self, text: str) -> str:
        if self.op == "replace":
            return text.replace(self.find, self.with_)
        if self.op == "prefix":
            return self.with_ + text
        if self.op == "suffix":
            return text + self.with_
        return text.upper() if self.op == "upper" else text.lower()


class ImportRules(BaseModel):
    """Rules applied to an export before importing: what to leave out, then what to change."""

    model_config = ConfigDict(title="Lockstep import rules", extra="forbid", populate_by_name=True)

    schema_: str | None = Field(default=None, alias="$schema")
    ignore_paths: list[str] = Field(default_factory=list, max_length=200,
                                    description="Secrets to leave out (globs over the exported paths)")
    ignore_keys: list[IgnoreKey] = Field(default_factory=list, max_length=200,
                                         description="Keys to leave out (key pattern, under a path glob)")
    transforms: list[Transform] = Field(default_factory=list, max_length=MAX_TRANSFORMS,
                                        description="Applied in order, after the ignores")

    @property
    def empty(self) -> bool:
        return not (self.ignore_paths or self.ignore_keys or self.transforms)


def rules_schema() -> dict:
    s = ImportRules.model_json_schema(by_alias=True)
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["$id"] = RULES_SCHEMA_URL
    return s


@dataclass
class Prepared:
    """An export after import rules: what would be compared or written."""

    doc: ExportDoc
    ignored_paths: int = 0
    ignored_keys: int = 0
    paths_changed: int = 0
    keys_changed: int = 0
    values_changed: int = 0
    # Problems that leave a secret out: two paths renamed onto one, two keys onto one, empty path…
    problems: dict[str, str] = field(default_factory=dict)
    # Target paths (after transforms) of keep entries: never written or deleted
    kept: list[str] = field(default_factory=list)
    # Target paths of entries left out by a problem: never deleted either, since the file meant them
    held: set[str] = field(default_factory=set)


def _norm(p: str) -> str:
    return "/".join(s for s in p.split("/") if s)


def prepare(doc: ExportDoc, rules: ImportRules | None) -> Prepared:
    """Apply ignores, then transforms in order. Each transform's path filter sees the path as
    it is at that step. The original document is left untouched."""
    rules = rules or ImportRules()
    ign_paths = [compile_glob(_norm(p)) for p in rules.ignore_paths if p.strip()]
    ign_keys = [(compile_glob(_norm(k.path) or "**"), k.key) for k in rules.ignore_keys]
    out = Prepared(doc=doc)
    work: list[tuple[str, str, dict | None]] = []  # (original path, current path, data; None = keep)
    for s in doc.secrets:
        if s.keep:  # ignores don't apply: a keep entry only protects
            work.append((s.path, s.path, None))
            continue
        if any(rx.match(s.path) for rx in ign_paths):
            out.ignored_paths += 1
            continue
        data = {}
        for k, v in s.data.items():
            if any(prx.match(s.path) and fnmatch.fnmatchcase(k, kg) for prx, kg in ign_keys):
                out.ignored_keys += 1
            else:
                data[k] = v
        if data:
            work.append((s.path, s.path, data))
        else:
            out.ignored_paths += 1  # every key was ignored

    for t in rules.transforms:
        prx = compile_glob(_norm(t.path) or "**")
        nxt = []
        for orig, path, data in work:
            if not prx.match(path):
                nxt.append((orig, path, data))
                continue
            if t.target == "paths":
                new = _norm(t.apply(path))
                if new != path:
                    out.paths_changed += 1
                nxt.append((orig, new, data))
                continue
            if data is None:
                nxt.append((orig, path, data))
                continue
            new_data: dict[str, Any] = {}
            for k, v in data.items():
                if not fnmatch.fnmatchcase(k, t.key):
                    nk, nv = k, v
                elif t.target == "keys":
                    nk, nv = t.apply(k), v
                    out.keys_changed += nk != k
                else:
                    nk = k
                    nv = t.apply(v) if isinstance(v, str) else v
                    out.values_changed += nv != v
                if nk in new_data or not nk:
                    out.problems[orig] = f"two keys become '{nk}'" if nk else f"key '{k}' becomes empty"
                new_data[nk] = nv
            nxt.append((orig, path, new_data))
        work = nxt

    by_path: dict[str, list[str]] = {}
    for orig, path, _ in work:
        by_path.setdefault(path, []).append(orig)
    for path, origs in by_path.items():
        if not path:
            for o in origs:
                out.problems[o] = "its path becomes empty"
        elif len(origs) > 1:
            for o in origs:
                out.problems[o] = f"{len(origs)} secrets become '{path}': {', '.join(sorted(origs))}"
    versions = {s.path: s for s in doc.secrets}
    secrets = [ExportSecret(path=path, version=versions[orig].version, updated=versions[orig].updated, data=data)
               for orig, path, data in work if orig not in out.problems and data is not None]
    out.kept = sorted(path for orig, path, data in work if orig not in out.problems and data is None)
    out.held = {path for orig, path, _ in work if orig in out.problems and path}
    out.doc = doc.model_copy(update={"secrets": sorted(secrets, key=lambda s: s.path)})
    return out


# --------------------------------------------------------------------------- an export as a read-only "Vault"


class FileVault:
    """Lets the comparison and sync code read an export like a KV v2 mount. Read-only:
    writes and capabilities say no, so an export can be a source but never a target."""

    def __init__(self, doc: ExportDoc):
        self.doc = doc
        self._secrets = {s.path: s for s in doc.secrets if not s.keep}

    async def __aenter__(self) -> "FileVault":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def kv_tree(self, mount: str, prefix: str = "", max_secrets: int = 5000, concurrency: int = 16) -> TreeResult:
        prefix = _norm(prefix)
        prefix = f"{prefix}/" if prefix else ""
        paths = sorted(p for p in self._secrets if p.startswith(prefix))
        return TreeResult(secrets=paths[:max_secrets], truncated=len(paths) > max_secrets)

    async def kv_read(self, mount: str, path: str, version: int | None = None) -> KvSecret:
        s = self._secrets.get(path)
        if s is None:
            return KvSecret(state="absent")
        return KvSecret(state="present", data=dict(s.data), version=s.version, updated=s.updated)

    async def kv_metadata(self, mount: str, path: str) -> dict:
        raise VaultError(404, "export files keep no version history", path)

    async def kv_write(self, mount: str, path: str, data: dict, cas: int | None) -> int:
        raise VaultError(403, "an export file is read-only", path)

    async def kv_delete(self, mount: str, path: str) -> None:
        raise VaultError(403, "an export file is read-only", path)

    async def capabilities(self, paths: list[str]) -> dict[str, list[str]]:
        return {p: [] for p in paths}
