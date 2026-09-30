"""HTTP requests and raw TCP connectivity.

Redirects are followed by hand, one hop at a time, so we can (a) record the
chain, (b) spot loops, and (c) re-check every hop against the SSRF guard.
"""

from __future__ import annotations

import errno
import socket
import time
import warnings
from urllib.parse import urljoin, urlsplit

import requests
from urllib3.exceptions import InsecureRequestWarning

from triage import __version__
from triage.lookup.target import address_class
from triage.model import Connectivity, Hop, HTTPResult

USER_AGENT = f"Triage/{__version__} (read-only domain diagnostics)"
TIMEOUT = 8
MAX_HOPS = 10
REDIRECT_CODES = {301, 302, 303, 307, 308}


def fetch(url: str) -> HTTPResult:
    result = HTTPResult(start_url=url)
    seen: set[str] = set()
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    verify = True

    for _ in range(MAX_HOPS):
        host = urlsplit(url).hostname or ""
        kind = address_class(host)
        if kind == "unresolvable":
            result.error = "The name doesn't resolve."
            return result
        if kind == "private":
            result.blocked = True
            result.error = f"{host} resolves to a private address, so it wasn't requested."
            return result
        start = time.monotonic()
        try:
            resp = _get(session, url, verify)
        except requests.exceptions.SSLError:
            # Fetch anyway with verification off, so a broken certificate
            # doesn't hide what the server returns. The TLS check reports it.
            verify = False
            result.cert_error_ignored = True
            try:
                resp = _get(session, url, verify)
            except requests.RequestException as e:
                result.error = _describe(e)
                return result
        except requests.RequestException as e:
            result.error = _describe(e)
            return result

        elapsed = int((time.monotonic() - start) * 1000)
        location = resp.headers.get("location")
        result.hops.append(Hop(url=url, status=resp.status_code, location=location))
        resp.close()

        if resp.status_code in REDIRECT_CODES and location:
            seen.add(url)
            nxt = urljoin(url, location)
            if nxt in seen:
                result.loop = True
                return result
            url = nxt
            continue

        result.final_url = url
        result.status = resp.status_code
        result.headers = {k.lower(): v for k, v in resp.headers.items()}
        result.elapsed_ms = elapsed
        return result

    result.loop = True  # more than MAX_HOPS redirects
    return result


def _get(session: requests.Session, url: str, verify: bool) -> requests.Response:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        # stream=True: we only need the status and headers, not the page body.
        return session.get(url, allow_redirects=False, timeout=TIMEOUT, verify=verify, stream=True)


def _describe(e: requests.RequestException) -> str:
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return f"Connection timed out after {TIMEOUT} s."
    if isinstance(e, requests.exceptions.ReadTimeout):
        return f"Connected, but the server didn't respond within {TIMEOUT} s."
    if isinstance(e, requests.exceptions.ConnectionError):
        text = str(e)
        if "Connection refused" in text:
            return "Connection refused: nothing is listening on that port."
        if "Name or service not known" in text or "nodename nor servname" in text:
            return "The name doesn't resolve."
        return "Couldn't connect to the server."
    return f"Request failed: {type(e).__name__}"


_ipv6_available: bool | None = None


def local_ipv6() -> bool:
    """Can THIS server reach the internet over IPv6? Many free hosts can't, and
    then an IPv6 failure says nothing about the customer's site."""
    global _ipv6_available
    if _ipv6_available is None:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 53))  # UDP connect sends nothing; it only picks a route
            _ipv6_available = True
        except OSError:
            _ipv6_available = False
    return _ipv6_available


def connect(address: str | None, family: str, port: int = 443, timeout: float = 4.0) -> Connectivity:
    result = Connectivity(family=family, address=address)
    if not address:
        result.error = "No address to connect to."
        return result
    if family == "IPv6" and not local_ipv6():
        result.inconclusive = True
        result.error = "This server has no IPv6 connectivity, so IPv6 couldn't be tested."
        return result
    af = socket.AF_INET6 if family == "IPv6" else socket.AF_INET
    start = time.monotonic()
    try:
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((address, port))
        result.ok = True
        result.ms = int((time.monotonic() - start) * 1000)
    except TimeoutError:
        result.error = f"Timed out after {timeout:g} s."
    except ConnectionRefusedError:
        result.error = f"Connection refused on port {port}."
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL):
            result.inconclusive = True
            result.error = "No route from this server; result inconclusive."
        else:
            result.error = f"Connection failed: {e.strerror or e}"
    return result
