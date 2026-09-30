"""DNS lookups. Named dnsq so it doesn't shadow the dnspython package.

Three views of the same domain:
  * records     -- what an ordinary recursive resolver returns
  * delegation  -- what the parent zone (the registry) delegates to, compared
                   with what the domain's own nameservers claim
  * propagation -- what several independent public resolvers return right now
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from triage.model import Delegation, DNSRecords, ResolverAnswer

TIMEOUT = 3.0
PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"),
    ("Cloudflare", "1.1.1.1"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]
VALIDATING_RESOLVER = "8.8.8.8"  # performs DNSSEC validation


def resolver(ips: list[str] | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ips or ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    r.timeout = TIMEOUT
    r.lifetime = TIMEOUT * 2
    return r


def query(r: dns.resolver.Resolver, name: str, rtype: str) -> tuple[list[str], int | None, str]:
    """Returns (values, ttl, status). Never raises."""
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return [], None, "nxdomain"
    except dns.resolver.NoNameservers:
        return [], None, "servfail"
    except dns.exception.Timeout:
        return [], None, "timeout"
    except dns.exception.DNSException:
        return [], None, "error"
    if ans.rrset is None:
        return [], None, "nodata"
    return [_clean(v.to_text()) for v in ans.rrset], ans.rrset.ttl, "ok"


def _clean(value: str) -> str:
    # "mail.example.com." -> "mail.example.com"; "10 mx.example.com." -> "10 mx.example.com".
    # TXT values are quoted, so they never end in a bare dot and are left alone.
    return value[:-1] if value.endswith(".") and not value.startswith('"') else value


def find_zone(host: str, r: dns.resolver.Resolver) -> str:
    """The zone the host lives in, e.g. www.example.co.uk -> example.co.uk."""
    try:
        zone = dns.resolver.zone_for_name(host, resolver=r).to_text().rstrip(".")
        if zone.count(".") >= 1:
            return zone
    except dns.exception.DNSException:
        pass
    # Fallback for names that don't resolve at all. Wrong for multi-label
    # suffixes like co.uk, which is acceptable for a name that doesn't exist.
    return ".".join(host.split(".")[-2:])


def records(host: str, apex: str, r: dns.resolver.Resolver) -> DNSRecords:
    rec = DNSRecords()
    a, rec.a_ttl, rec.status = query(r, host, "A")
    rec.a = a
    rec.aaaa, _, _ = query(r, host, "AAAA")
    rec.cname_chain = _cname_chain(host, r)
    rec.ns, _, _ = query(r, apex, "NS")
    rec.mx, _, _ = query(r, apex, "MX")
    rec.txt, _, _ = query(r, apex, "TXT")
    rec.caa, _, _ = query(r, apex, "CAA")
    rec.dmarc, _, _ = query(r, f"_dmarc.{apex}", "TXT")
    soa, _, _ = query(r, apex, "SOA")
    rec.soa = soa[0] if soa else None
    return rec


def _cname_chain(host: str, r: dns.resolver.Resolver, limit: int = 8) -> list[str]:
    chain, name = [], host
    for _ in range(limit):
        values, _, status = query(r, name, "CNAME")
        if status != "ok" or not values:
            break
        name = values[0]
        chain.append(name)
    return chain


def _nonrecursive(qname: str, rtype: str, server_ip: str) -> dns.message.Message | None:
    q = dns.message.make_query(qname, rtype)
    q.flags &= ~dns.flags.RD  # ask the server what IT knows; don't let it recurse
    try:
        resp, _ = dns.query.udp_with_fallback(q, server_ip, timeout=TIMEOUT)
        return resp
    except (dns.exception.DNSException, OSError):
        return None


def _ns_names(resp: dns.message.Message, owner: str, sections) -> set[str]:
    want = dns.name.from_text(owner)
    out: set[str] = set()
    for section in sections:
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == want:
                out |= {x.target.to_text().rstrip(".").lower() for x in rrset}
    return out


def _glue(resp: dns.message.Message) -> dict[str, str]:
    glue = {}
    for rrset in resp.additional:
        if rrset.rdtype == dns.rdatatype.A:
            glue[rrset.name.to_text().rstrip(".").lower()] = rrset[0].to_text()
    return glue


def delegation(apex: str, r: dns.resolver.Resolver) -> Delegation:
    d = _delegation(apex, r)
    # DNSSEC only needs recursive queries, so check it even if the direct
    # nameserver queries above failed.
    ds, _, _ = query(r, apex, "DS")
    d.ds_present = bool(ds)
    if ds:
        d.dnssec_broken = _dnssec_broken(apex)
    # Sanity check on our own vantage point: if every nameserver looks broken
    # but ordinary resolvers still resolve the domain, the contradiction means
    # direct queries from this server are being intercepted or blocked, not
    # that the domain is broken. Report "couldn't check", never an error.
    if d.parent_ns and len(d.lame) >= len(d.parent_ns):
        ns, _, status = query(r, apex, "NS")
        if status == "ok" and ns:
            d.vantage_blocked = True
            d.lame, d.child_ns = [], []
            d.error = "The domain's nameservers couldn't be queried directly from this server."
    return d


def _delegation(apex: str, r: dns.resolver.Resolver) -> Delegation:
    d = Delegation()
    try:
        parent = dns.resolver.zone_for_name(dns.name.from_text(apex).parent(), resolver=r)
    except dns.exception.DNSException as e:
        d.error = f"Couldn't find the parent zone: {e}"
        return d
    d.parent_zone = parent.to_text().rstrip(".")
    parent_servers, _, _ = query(r, d.parent_zone, "NS")

    glue: dict[str, str] = {}
    for server in parent_servers[:3]:
        ips, _, _ = query(r, server, "A")
        if not ips:
            continue
        resp = _nonrecursive(apex, "NS", ips[0])
        if resp is None:
            continue
        if resp.rcode() == dns.rcode.NXDOMAIN:
            d.parent_nxdomain = True
            return d
        names = _ns_names(resp, apex, (resp.authority, resp.answer))
        if names:
            d.parent_ns = sorted(names)
            glue = _glue(resp)
            break
    if not d.parent_ns:
        d.error = "The parent zone's servers didn't answer."
        return d

    child: set[str] = set()
    for ns in d.parent_ns:
        ip = glue.get(ns)
        if not ip:
            ips, _, _ = query(r, ns, "A")
            ip = ips[0] if ips else None
        if not ip:
            d.lame.append((ns, "the nameserver's own name doesn't resolve"))
            continue
        resp = _nonrecursive(apex, "NS", ip)
        if resp is None:
            d.lame.append((ns, "no response (timed out)"))
        elif resp.rcode() == dns.rcode.REFUSED:
            d.lame.append((ns, "refused to answer for this domain"))
        elif not resp.flags & dns.flags.AA:
            d.lame.append((ns, "answers, but isn't authoritative for this domain"))
        else:
            child |= _ns_names(resp, apex, (resp.answer,))
    d.child_ns = sorted(child)
    return d


def _dnssec_broken(name: str) -> bool | None:
    """A validating resolver returns SERVFAIL for a bogus signature, but answers
    normally when told to skip validation (CD flag). That pair is the signature
    of broken DNSSEC, e.g. a stale DS record left behind after a DNS move."""
    try:
        q = dns.message.make_query(name, "SOA", want_dnssec=True)
        strict = dns.query.udp(q, VALIDATING_RESOLVER, timeout=TIMEOUT)
        if strict.rcode() != dns.rcode.SERVFAIL:
            return False
        q_cd = dns.message.make_query(name, "SOA", want_dnssec=True)
        q_cd.flags |= dns.flags.CD
        relaxed = dns.query.udp(q_cd, VALIDATING_RESOLVER, timeout=TIMEOUT)
        return relaxed.rcode() == dns.rcode.NOERROR
    except (dns.exception.DNSException, OSError):
        return None


def propagation(host: str, apex: str) -> list[ResolverAnswer]:
    out = []
    for name, ip in PUBLIC_RESOLVERS:
        r = resolver([ip])
        a, _, status = query(r, host, "A")
        ns, _, _ = query(r, apex, "NS")
        out.append(ResolverAnswer(name=name, ip=ip, a=sorted(a), ns=sorted(x.lower() for x in ns), status=status))
    return out


def authoritative_a(host: str, nameservers: list[str], r: dns.resolver.Resolver) -> list[str] | None:
    """A records straight from the domain's own nameserver. None if it only has
    a CNAME (the answer then lives in another zone) or didn't answer."""
    for ns in nameservers[:2]:
        ips, _, _ = query(r, ns, "A")
        if not ips:
            continue
        resp = _nonrecursive(host, "A", ips[0])
        if resp is None or not resp.flags & dns.flags.AA:
            continue
        want = dns.name.from_text(host)
        for rrset in resp.answer:
            if rrset.name == want and rrset.rdtype == dns.rdatatype.CNAME:
                return None
            if rrset.name == want and rrset.rdtype == dns.rdatatype.A:
                return sorted(x.to_text() for x in rrset)
        return []
    return None
