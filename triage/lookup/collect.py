"""Run every lookup for one target, in parallel, and return an Observation.

Each lookup already converts its own failures into data (error fields), so
one slow or broken source never takes the whole diagnosis down.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from triage.lookup import dnsq, providers, rdap, tls, web
from triage.lookup.target import parse_input
from triage.model import Observation


def counterpart(host: str, apex: str) -> str | None:
    if host == apex:
        return f"www.{apex}"
    if host == f"www.{apex}":
        return apex
    return None


def collect(raw: str, expected: str | None = None) -> Observation:
    start = time.monotonic()
    host, url = parse_input(raw)
    r = dnsq.resolver()
    apex = dnsq.find_zone(host, r)
    obs = Observation(
        host=host, url=url, apex=apex, other_host=counterpart(host, apex),
        expected=(expected or "").strip() or None,
        checked_at=datetime.now(timezone.utc),
    )
    https_url = url if url.startswith("https://") else "https://" + url.split("://", 1)[1]

    with ThreadPoolExecutor(max_workers=10) as pool:
        f_records = pool.submit(dnsq.records, host, apex, r)
        f_deleg = pool.submit(dnsq.delegation, apex, r)
        f_prop = pool.submit(dnsq.propagation, host, apex)
        f_reg = pool.submit(rdap.lookup, apex)
        f_https = pool.submit(web.fetch, https_url)
        f_http = pool.submit(web.fetch, f"http://{host}/")
        f_tls = pool.submit(tls.observe, host)
        f_other = pool.submit(web.fetch, f"https://{obs.other_host}/") if obs.other_host else None

        obs.dns = f_records.result()
        obs.delegation = f_deleg.result()
        f_v4 = pool.submit(web.connect, obs.dns.a[0] if obs.dns.a else None, "IPv4")
        f_v6 = pool.submit(web.connect, obs.dns.aaaa[0] if obs.dns.aaaa else None, "IPv6") if obs.dns.aaaa else None
        f_auth = pool.submit(dnsq.authoritative_a, host, obs.delegation.child_ns or obs.delegation.parent_ns, r)

        obs.resolvers = f_prop.result()
        obs.registration = f_reg.result()
        obs.https = f_https.result()
        obs.http = f_http.result()
        obs.tls = f_tls.result()
        obs.other = f_other.result() if f_other else None
        obs.ipv4 = f_v4.result()
        obs.ipv6 = f_v6.result() if f_v6 else None
        obs.authoritative_a = f_auth.result()

    obs.dns_provider = providers.dns_provider(obs.delegation.parent_ns or obs.dns.ns)
    obs.cdn = providers.cdn(obs.https.headers) if obs.https else None
    obs.duration_ms = int((time.monotonic() - start) * 1000)
    return obs
