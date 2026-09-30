"""Turn whatever the engineer pastes into a hostname + URL, and refuse targets
that would make this server attack its own network (SSRF)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


def parse_input(raw: str) -> tuple[str, str]:
    """'Example.com/shop?x=1' -> ('example.com', 'https://example.com/shop?x=1')."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Paste a link or domain to check.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// links can be checked.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError("That doesn't look like a link or domain.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"'{host}' isn't a valid domain name.") from e
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name rather than an IP address.")
    if "." not in host:
        raise ValueError(f"'{host}' isn't a full domain name.")
    path = parts.path or "/"
    url = f"{parts.scheme}://{host}{path}" + (f"?{parts.query}" if parts.query else "")
    return host, url


def address_class(host: str) -> str:
    """'public', 'private' (refuse to connect), or 'unresolvable'."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return "unresolvable"
    addrs = {info[4][0] for info in infos}
    if addrs and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs):
        return "public"
    return "private"


def is_public_host(host: str) -> bool:
    """True only if every address the host resolves to is publicly routable.

    Without this, anyone could point the tool at 'localhost' or a cloud
    metadata address and read internal services through our server. Known
    limitation: the HTTP client resolves the name again when it connects, so a
    DNS-rebinding attacker could still race this check. Documented in README.
    """
    return address_class(host) == "public"
