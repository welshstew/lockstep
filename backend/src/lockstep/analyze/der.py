"""A minimal DER reader: just enough to recognise structures `cryptography` won't
identify for us (PKCS#12 without its password, JKS key blobs)."""

from __future__ import annotations

from dataclasses import dataclass


class DerError(ValueError):
    pass


@dataclass
class Tlv:
    tag: int
    value: bytes
    end: int  # offset just past this element


def read(buf: bytes, pos: int = 0) -> Tlv:
    if pos + 2 > len(buf):
        raise DerError("truncated")
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise DerError("bad length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise DerError("truncated value")
    return Tlv(tag, buf[pos:pos + length], pos + length)


def children(value: bytes) -> list[Tlv]:
    out, pos = [], 0
    while pos < len(value):
        t = read(value, pos)
        out.append(t)
        pos = t.end
    return out


def oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    parts = [value[0] // 40, value[0] % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


PKCS7_DATA = "1.2.840.113549.1.7.1"
PKCS7_SIGNED = "1.2.840.113549.1.7.2"


def is_pfx(buf: bytes) -> bool:
    """PKCS#12 PFX: SEQUENCE { INTEGER 3, ContentInfo { OID data|signedData, ... }, ... }."""
    try:
        top = read(buf)
        if top.tag != 0x30 or top.end != len(buf):
            return False
        kids = children(top.value)
        if len(kids) < 2 or kids[0].tag != 0x02 or kids[0].value != b"\x03" or kids[1].tag != 0x30:
            return False
        ci = children(kids[1].value)
        return bool(ci) and ci[0].tag == 0x06 and oid(ci[0].value) in (PKCS7_DATA, PKCS7_SIGNED)
    except DerError:
        return False


def is_der_sequence(buf: bytes) -> bool:
    try:
        t = read(buf)
        return t.tag == 0x30 and t.end == len(buf)
    except DerError:
        return False
