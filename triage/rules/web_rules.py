from __future__ import annotations

from triage.model import HTTPResult, Observation
from triage.rules import Diagnosis, rule


def works(r: HTTPResult | None) -> bool:
    return bool(r and r.ok and r.status is not None and r.status < 400)


def _has_address(obs: Observation) -> bool:
    return bool(obs.dns.a or obs.dns.aaaa)


@rule("NET-02")
def server_unreachable(obs: Observation) -> Diagnosis | None:
    if not _has_address(obs) or not obs.https or not obs.http:
        return None
    if obs.https.blocked or obs.https.status is not None or obs.http.status is not None or obs.https.loop:
        return None
    v4 = obs.ipv4
    if v4 and v4.inconclusive:
        return None
    return Diagnosis(
        id="NET-02", level="error", step="server",
        title="The web server isn't responding",
        summary="DNS points to an address, but nothing answers there over HTTPS or HTTP.",
        evidence=[("HTTPS", obs.https.error or "no response"), ("HTTP", obs.http.error or "no response"),
                  ("Address", ", ".join(obs.dns.a or obs.dns.aaaa))],
        fix=["Check the server or hosting account is running and the firewall allows ports 80 and 443.",
             "If the site moved hosts, check the DNS records point to the new server."],
        reply=("Your domain points to a server that isn't responding right now. Please check with your hosting "
               "provider that the server is running."),
        confidence="High" if v4 and not v4.ok else "Medium",
        confidence_reason="HTTPS and HTTP both failed" + (", and a raw connection to port 443 failed." if v4 and not v4.ok else "."),
    )


@rule("HTTP-01")
def server_error(obs: Observation) -> Diagnosis | None:
    r = obs.https
    if not r or r.status is None or r.status < 500:
        return None
    via = f" via {obs.cdn}" if obs.cdn else ""
    behind_cdn = obs.cdn and r.status in (502, 503, 504)
    return Diagnosis(
        id="HTTP-01", level="error", step="server",
        title=f"The site returns an error page (HTTP {r.status})",
        summary=(f"{obs.cdn} answered, but couldn't get a good response from the website's own server behind it. "
                 "The problem is almost always that server, not the CDN." if behind_cdn
                 else "The server is reachable but fails to produce the page."),
        evidence=[("Final URL", r.final_url or r.start_url), ("Status", f"{r.status}{via}"),
                  ("server header", r.headers.get("server", "not sent"))],
        fix=(["Check the origin server (the host behind the CDN) is up and responding quickly.",
              "Look at the origin's error logs around the time of the check."] if behind_cdn
             else ["Check the application and web server error logs.", "Check recent deployments or plugin updates."]),
        reply=("Your site's server is returning an error instead of the page. Your developer or hosting provider "
               "will need to check the server's error logs."),
        confidence_reason="Observed the status code directly.",
    )


@rule("HTTP-02")
def client_error(obs: Observation) -> Diagnosis | None:
    r = obs.https
    if not r or r.status is None or not 400 <= r.status < 500:
        return None
    if r.status in (401, 403, 429):
        return Diagnosis(
            id="HTTP-02", level="warning", step="server",
            title=f"The site refused our request (HTTP {r.status})",
            summary=("This is often bot protection blocking automated tools rather than a real outage. "
                     "Check in a normal browser before drawing conclusions."),
            evidence=[("Final URL", r.final_url or r.start_url), ("Status", str(r.status))],
            fix=["Open the site in a browser. If it loads there, this is bot protection and can be ignored."],
            confidence="Low", confidence_reason="Security tools block automated requests like this one.",
        )
    return Diagnosis(
        id="HTTP-02", level="warning", step="server",
        title=f"The page returns HTTP {r.status}",
        summary="The server works, but the requested page doesn't exist or can't be served.",
        evidence=[("Final URL", r.final_url or r.start_url), ("Status", str(r.status))],
        fix=["Check the link is correct and the page still exists.", "Check recent changes to URLs or redirects."],
        reply=f"The server is working, but the page at {r.final_url or r.start_url} returns an error ({r.status}). The link may be outdated.",
        confidence_reason="Observed the status code directly.",
    )


@rule("HTTP-03")
def redirect_loop(obs: Observation) -> Diagnosis | None:
    looping = [r for r in (obs.https, obs.http) if r and r.loop]
    if not looping:
        return None
    r = looping[0]
    chain = " → ".join(f"{h.status} {h.url}" for h in r.hops[:6])
    return Diagnosis(
        id="HTTP-03", level="error", step="server",
        title="The site redirects in a loop",
        summary=("Browsers give up with 'too many redirects'. A classic cause is a CDN or proxy talking to the server over "
                 "HTTP while the server redirects everything to HTTPS (or the reverse)."),
        evidence=[("Redirects", chain + (" …" if len(r.hops) > 6 else ""))],
        fix=["Make sure only one layer (the CDN/proxy or the server, not both) forces HTTPS.",
             "Check the SSL mode between any CDN and the server matches how the server expects to be reached."],
        reply=("Your site is stuck redirecting to itself, so browsers show a 'too many redirects' error. It's usually a "
               "settings mismatch between your hosting and any CDN or proxy in front of it."),
        confidence_reason="Saw the same URL repeat in the redirect chain.",
    )


@rule("HTTP-04")
def https_setup(obs: Observation) -> Diagnosis | None:
    if not obs.http or not works(obs.http):
        return None
    if works(obs.https) and (obs.http.final_url or "").startswith("http://"):
        return Diagnosis(
            id="HTTP-04", level="warning", step="server",
            title="Plain http:// doesn't redirect to https://",
            summary="Visitors who type the address without https:// get an unencrypted page and may see a 'not secure' label.",
            evidence=[("http://", f"{obs.http.status} at {obs.http.final_url}")],
            fix=["Add a permanent (301) redirect from http:// to https://."],
            confidence_reason="Requested the http:// address and followed its redirects.",
        )
    if not works(obs.https) and not (obs.https and obs.https.status):
        return Diagnosis(
            id="HTTP-04", level="warning", step="tls",
            title="The site only works over plain http://",
            summary="HTTPS doesn't work, so browsers that default to HTTPS (most now do) may fail or show a warning.",
            evidence=[("https://", (obs.https.error if obs.https else None) or "failed"), ("http://", f"{obs.http.status}")],
            fix=["Install a certificate and enable HTTPS on the server."],
            reply="Your site only loads over an insecure connection. Enabling HTTPS with a certificate will fix browser warnings.",
            confidence_reason="HTTPS failed while HTTP succeeded.",
        )
    return None


@rule("NET-01")
def ipv6_broken(obs: Observation) -> Diagnosis | None:
    v4, v6 = obs.ipv4, obs.ipv6
    if not v6 or v6.ok or v6.inconclusive or not (v4 and v4.ok):
        return None
    return Diagnosis(
        id="NET-01", level="warning", step="server",
        title="The site's IPv6 address doesn't respond",
        summary=("IPv4 works, but the AAAA record points to an address that doesn't answer. Visitors on IPv6 networks, "
                 "including many mobile carriers, may see the site as slow or down."),
        evidence=[("IPv4", f"{v4.address} connected in {v4.ms} ms"), ("IPv6", f"{v6.address}: {v6.error}")],
        fix=["Fix IPv6 on the server, or remove the AAAA record until it works."],
        reply=("Your site works on most connections but not on IPv6 networks, which many mobile providers use. "
               "Your host needs to fix IPv6 or remove the IPv6 DNS record."),
        confidence_reason="Direct connection test over both IPv4 and IPv6.",
    )


@rule("HOST-01")
def counterpart_differs(obs: Observation) -> Diagnosis | None:
    if not obs.other_host or obs.other is None:
        return None
    main_ok, other_ok = works(obs.https), works(obs.other)
    if main_ok and not other_ok:
        if obs.other.status in (401, 403, 429):
            return None  # likely bot protection on the other name; not evidence of a fault
        if obs.other.error == "The name doesn't resolve.":
            return Diagnosis(
                id="HOST-01", level="info", step="dns",
                title=f"{obs.other_host} has no DNS record",
                summary=(f"Fine if that's intentional, but anyone typing {obs.other_host} gets an error. "
                         f"Worth checking if the customer says the site is down and {obs.host} works for you."),
                evidence=[(obs.host, f"{obs.https.status} OK"), (obs.other_host, "no DNS record")],
                fix=[f"If visitors use it, add a record for {obs.other_host} and redirect it to {obs.host}."],
                confidence="Medium", confidence_reason="Many sites deliberately use only one form of the address.",
            )
        problem = obs.other.error or (f"HTTP {obs.other.status}" if obs.other.status else "doesn't load")
        return Diagnosis(
            id="HOST-01", level="warning", step="dns",
            title=f"{obs.other_host} doesn't work, but {obs.host} does",
            summary="The name exists but doesn't load. The customer, or their visitors, may be typing that version of the address.",
            evidence=[(obs.host, f"{obs.https.status} OK"), (obs.other_host, problem)],
            fix=[f"Point {obs.other_host} at the same site (a CNAME for www, or matching A records) and redirect one to the other."],
            reply=(f"{obs.host} works, but {obs.other_host} doesn't. Visitors typing that version of the address will "
                   "see an error until it's pointed at the same site."),
            confidence_reason="Requested both versions of the address.",
        )
    if other_ok and not main_ok:
        return Diagnosis(
            id="HOST-01", level="info", step="dns",
            title=f"{obs.other_host} works",
            summary=f"Only {obs.host} is affected. That narrows the problem to its own DNS record or configuration.",
            evidence=[(obs.other_host, f"{obs.other.status} at {obs.other.final_url}")],
            confidence_reason="Requested both versions of the address.",
        )
    return None
