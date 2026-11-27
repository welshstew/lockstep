"""Custom Vault addresses: what a user may point the server at.

A custom address is normalised to its origin (scheme://host[:port]) and the allowed-address
patterns are matched against that, never against the raw text. The host is resolved and refused
if any of its addresses is loopback, link-local (169.254.169.254 among them), private, unique-local
or otherwise not public, unless LOCKSTEP_CUSTOM_ALLOW_PRIVATE is set. The client then connects to
the address that was checked (see vault.VaultClient), so a DNS answer can't change in between.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from .config import Settings


class AddressError(ValueError):
    """A custom address that isn't allowed, with a message for the user."""


DEFAULT_PORTS = {"http": 80, "https": 443}


def normalise(url: str) -> tuple[str, str, int]:
    """(origin, host, port) of a custom address. Only scheme://host[:port] is accepted, with an
    optional trailing slash: no user name or password, path, query or fragment."""
    try:
        u = urlsplit(url.strip())
        port = u.port
    except ValueError as e:
        raise AddressError(f"Not a valid address: {e}") from e
    scheme = u.scheme.lower()
    if scheme not in DEFAULT_PORTS or not u.hostname:
        raise AddressError("The Vault address must be http(s)://host[:port]")
    if "@" in u.netloc:
        raise AddressError("The Vault address can't contain a user name or password")
    if u.path not in ("", "/") or u.query or u.fragment or url.strip().endswith(("?", "#")):
        raise AddressError("The Vault address must be just http(s)://host[:port], without a path or query")
    host = u.hostname.rstrip(".").lower()
    shown = f"[{host}]" if ":" in host else host
    port = port or DEFAULT_PORTS[scheme]
    origin = f"{scheme}://{shown}" + ("" if port == DEFAULT_PORTS[scheme] else f":{port}")
    return origin, host, port


def allowed_by_patterns(origin: str, settings: Settings) -> bool:
    return not settings.custom_url_patterns or any(re.fullmatch(p, origin) for p in settings.custom_url_patterns)


def check_origin(url: str, settings: Settings) -> str:
    """The normalised origin of a custom address, if custom addresses and the patterns allow it."""
    if not settings.allow_custom_connections:
        raise AddressError("Custom Vault addresses are turned off on this server: pick one of its Vaults")
    origin, _, _ = normalise(url)
    if not allowed_by_patterns(origin, settings):
        raise AddressError("This Vault address isn't on the allowed list")
    return origin


def _refused(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast:
        return True
    return not allow_private and not ip.is_global


async def _getaddrinfo(host: str, port: int):
    return await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)


async def resolve(host: str, port: int, settings: Settings) -> str:
    """The address to connect to for `host`, after checking every address it resolves to."""
    try:
        addrs = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            infos = await _getaddrinfo(host, port)
        except OSError as e:
            raise AddressError(f"Can't resolve {host}: {e.strerror or e}") from e
        addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
    if not addrs:
        raise AddressError(f"Can't resolve {host}")
    for a in addrs:
        if _refused(ipaddress.ip_address(a.split("%")[0]), settings.custom_allow_private):
            raise AddressError(f"{host} is {a}, a private or local address: this server doesn't connect to those "
                               "for custom Vault addresses (LOCKSTEP_CUSTOM_ALLOW_PRIVATE=true allows it)")
    return addrs[0]
