"""Each test starts from a healthy domain, breaks one thing, and checks that
exactly the expected rule fires. The healthy baseline must produce nothing."""

from datetime import datetime, timedelta, timezone

import pytest

from triage import rules
from triage.lookup import tls as T
from triage.model import (CertInfo, Connectivity, Delegation, DNSRecords, Hop, HTTPResult,
                          Observation, Registration, ResolverAnswer, TLSResult)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
NS = ["ns1.hostco.net", "ns2.hostco.net"]


def ok_http(url, status=200, headers=None):
    return HTTPResult(start_url=url, hops=[Hop(url, status)], final_url=url, status=status,
                      headers=headers or {"server": "nginx"}, elapsed_ms=120)


def healthy(**overrides) -> Observation:
    obs = Observation(
        host="www.example.com", url="https://www.example.com/", apex="example.com",
        other_host="example.com", expected=None, checked_at=NOW,
        dns=DNSRecords(a=["203.0.113.10"], aaaa=["2001:db8::10"], a_ttl=300, ns=NS),
        delegation=Delegation(parent_zone="com", parent_ns=NS, child_ns=NS, ds_present=False),
        resolvers=[ResolverAnswer(n, ip, a=["203.0.113.10"], ns=NS) for n, ip in
                   [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Quad9", "9.9.9.9"), ("OpenDNS", "208.67.222.222")]],
        https=ok_http("https://www.example.com/"),
        http=HTTPResult(start_url="http://www.example.com/",
                        hops=[Hop("http://www.example.com/", 301, "https://www.example.com/"), Hop("https://www.example.com/", 200)],
                        final_url="https://www.example.com/", status=200, elapsed_ms=90),
        other=ok_http("https://example.com/"),
        tls=TLSResult(host="www.example.com", verified=True, version="TLSv1.3",
                      cert=CertInfo("example.com", "Example CA / R1", ["example.com", "www.example.com"],
                                    NOW - timedelta(days=30), NOW + timedelta(days=60), False)),
        ipv4=Connectivity("IPv4", "203.0.113.10", ok=True, ms=20),
        ipv6=Connectivity("IPv6", "2001:db8::10", ok=True, ms=25),
        registration=Registration(domain="example.com", registrar="Example Registrar", expires=NOW + timedelta(days=300)),
    )
    for key, value in overrides.items():
        setattr(obs, key, value)
    return obs


def fired(obs, level=None):
    return {d.id for d in rules.run(obs) if level is None or d.level == level}


def test_healthy_domain_produces_no_diagnoses():
    assert fired(healthy()) == set()


# --- DNS -------------------------------------------------------------------

def test_dns01_missing_name_suggests_counterpart():
    obs = healthy(dns=DNSRecords(status="nxdomain", ns=NS), https=HTTPResult("https://www.example.com/", error="The name doesn't resolve."),
                  http=HTTPResult("http://www.example.com/", error="The name doesn't resolve."), tls=None, ipv4=None, ipv6=None)
    diags = {d.id: d for d in rules.run(obs)}
    assert "DNS-01" in diags and diags["DNS-01"].level == "error"
    assert any("example.com" in f for f in diags["DNS-01"].fix)
    assert "NET-02" not in diags  # no address, so "server unreachable" would be wrong


def test_dns02_dangling_cname():
    obs = healthy(dns=DNSRecords(status="nodata", cname_chain=["old-app.somehost.example"], ns=NS))
    d = next(d for d in rules.run(obs) if d.id == "DNS-02")
    assert "old-app.somehost.example" in d.title + d.summary


def test_dns03_servfail_but_not_when_dnssec_explains_it():
    base = dict(dns=DNSRecords(status="servfail", ns=NS))
    assert "DNS-03" in fired(healthy(**base))
    broken = healthy(**base, delegation=Delegation(parent_ns=NS, child_ns=NS, ds_present=True, dnssec_broken=True))
    assert "DNS-03" not in fired(broken) and "DNS-05" in fired(broken)


def test_dns07_nameserver_disagreement_is_a_warning():
    obs = healthy()
    obs.resolvers[2].ns = ["old1.oldhost.example", "old2.oldhost.example"]
    assert fired(obs) == {"DNS-07"} and fired(obs, "warning") == {"DNS-07"}


def test_dns07_disjoint_addresses_is_only_low_confidence_info():
    obs = healthy()
    obs.resolvers[0].a = ["198.51.100.1"]
    d = next(d for d in rules.run(obs) if d.id == "DNS-07")
    assert d.level == "info" and d.confidence == "Low"


# --- Delegation --------------------------------------------------------------

def test_del01_fires_when_registry_points_elsewhere():
    namecheap = ["dns1.registrar-servers.com", "dns2.registrar-servers.com"]
    obs = healthy(expected="Route 53", delegation=Delegation(parent_zone="com", parent_ns=namecheap, child_ns=namecheap, ds_present=False))
    for r in obs.resolvers:
        r.ns = namecheap
    diags = {d.id: d for d in rules.run(obs)}
    assert "Namecheap" in diags["DEL-01"].title
    assert diags["DEL-01"].level == "error"
    assert diags["DEL-01"].confidence == "High"  # all 4 resolvers agree with the registry


def test_del01_matches_provider_by_name_and_alias():
    route53 = ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"]
    for expected in ("Route 53", "aws", "Amazon Route 53"):
        obs = healthy(expected=expected, delegation=Delegation(parent_ns=route53, child_ns=route53, ds_present=False))
        obs.dns.ns = route53
        for r in obs.resolvers:
            r.ns = route53
        assert "DEL-01" not in fired(obs), expected


def test_del01_silent_when_provider_unrecognised():
    # hostco.net isn't a known provider: "can't tell" must not become an error.
    assert "DEL-01" not in fired(healthy(expected="SomeHost"))


def test_del01_matches_explicit_nameservers():
    assert "DEL-01" not in fired(healthy(expected="ns1.hostco.net, ns2.hostco.net"))
    assert "DEL-01" in fired(healthy(expected="ns1.newhost.example ns2.newhost.example"))


def test_del02_registry_and_zone_disagree():
    obs = healthy(delegation=Delegation(parent_ns=NS, child_ns=["ns1.newhost.example"], ds_present=False))
    assert fired(obs) == {"DEL-02"}


def test_del03_partial_vs_total_lame():
    partial = healthy(delegation=Delegation(parent_ns=NS, child_ns=NS[:1], lame=[(NS[1], "no response (timed out)")], ds_present=False))
    assert {d.level for d in rules.run(partial) if d.id == "DEL-03"} == {"warning"}
    total = healthy(delegation=Delegation(parent_ns=NS, lame=[(n, "refused") for n in NS], ds_present=False))
    assert {d.level for d in rules.run(total) if d.id == "DEL-03"} == {"error"}


# --- TLS -----------------------------------------------------------------------

def _cert(days_left, lifetime=90, sans=("www.example.com",), self_signed=False):
    end = NOW + timedelta(days=days_left)
    return CertInfo("example.com", "Example CA", list(sans), end - timedelta(days=lifetime), end, self_signed)


def test_tls01_expired_reported_once():
    obs = healthy(tls=TLSResult("www.example.com", verified=False, verify_code=T.ERR_EXPIRED, verify_message="certificate has expired", cert=_cert(-3)))
    ids = [d.id for d in rules.run(obs)]
    assert ids.count("TLS-01") == 1 and "TLS-02" not in ids


@pytest.mark.parametrize("days_left,lifetime,level", [(5, 90, "warning"), (25, 90, "info"), (60, 398, None), (14, 47, "info")])
def test_tls01_expiry_thresholds_scale_with_lifetime(days_left, lifetime, level):
    obs = healthy(tls=TLSResult("www.example.com", verified=True, cert=_cert(days_left, lifetime)))
    got = {d.level for d in rules.run(obs) if d.id == "TLS-01"}
    assert got == ({level} if level else set())


def test_tls02_hostname_mismatch_names_what_cert_covers():
    obs = healthy(tls=TLSResult("www.example.com", verified=False, verify_code=T.ERR_HOSTNAME_MISMATCH,
                                verify_message="Hostname mismatch", cert=_cert(60, sans=("other-site.example",))))
    d = next(d for d in rules.run(obs) if d.id == "TLS-02")
    assert "other-site.example" in d.summary


def test_tls02_incomplete_chain_is_a_warning_only_when_proven():
    proven = healthy(tls=TLSResult("www.example.com", verified=False, verify_code=T.ERR_NO_LOCAL_ISSUER,
                                   verify_message="unable to get local issuer certificate", cert=_cert(60), chain_length=1))
    assert [d.level for d in rules.run(proven) if d.id == "TLS-02"] == ["warning"]
    unknown = healthy(tls=TLSResult("www.example.com", verified=False, verify_code=T.ERR_NO_LOCAL_ISSUER,
                                    verify_message="unable to get local issuer certificate", cert=_cert(60)))
    d = next(d for d in rules.run(unknown) if d.id == "TLS-02")
    assert d.level == "error" and d.confidence == "Medium"


# --- Web -----------------------------------------------------------------------

def test_net02_unreachable_server():
    obs = healthy(https=HTTPResult("https://www.example.com/", error="Connection timed out after 8 s."),
                  http=HTTPResult("http://www.example.com/", error="Connection timed out after 8 s."),
                  ipv4=Connectivity("IPv4", "203.0.113.10", ok=False, error="Timed out after 4 s."),
                  ipv6=Connectivity("IPv6", "2001:db8::10", ok=False, error="Timed out after 4 s."),
                  other=HTTPResult("https://example.com/", error="Connection timed out after 8 s."))
    diags = {d.id: d for d in rules.run(obs)}
    assert diags["NET-02"].confidence == "High"
    assert "NET-01" not in diags  # IPv6 isn't the story when IPv4 is down too


def test_http01_origin_error_behind_cdn_blames_origin():
    obs = healthy(https=ok_http("https://www.example.com/", 502, {"server": "cloudflare", "cf-ray": "x"}))
    obs.cdn = "Cloudflare"
    d = next(d for d in rules.run(obs) if d.id == "HTTP-01")
    assert "server behind it" in d.summary


def test_http02_403_is_low_confidence():
    obs = healthy(https=ok_http("https://www.example.com/", 403))
    d = next(d for d in rules.run(obs) if d.id == "HTTP-02")
    assert d.confidence == "Low" and d.level == "warning"


def test_http03_redirect_loop():
    loop = HTTPResult("https://www.example.com/", hops=[Hop("https://www.example.com/", 301, "https://example.com/"),
                                                      Hop("https://example.com/", 301, "https://www.example.com/")], loop=True)
    assert "HTTP-03" in fired(healthy(https=loop))


def test_http04_missing_https_redirect():
    plain = ok_http("http://www.example.com/")
    assert fired(healthy(http=plain)) == {"HTTP-04"}


def test_net01_ipv6_broken_but_not_when_we_cannot_test():
    broken = healthy(ipv6=Connectivity("IPv6", "2001:db8::10", ok=False, error="Timed out after 4 s."))
    assert fired(broken) == {"NET-01"}
    untestable = healthy(ipv6=Connectivity("IPv6", "2001:db8::10", inconclusive=True, error="This server has no IPv6"))
    assert fired(untestable) == set()


def test_host01_counterpart_broken_vs_missing():
    broken = healthy(other=HTTPResult("https://example.com/", error="Connection refused: nothing is listening on that port."))
    assert fired(broken, "warning") == {"HOST-01"}
    missing = healthy(other=HTTPResult("https://example.com/", error="The name doesn't resolve."))
    assert fired(missing, "warning") == set() and "HOST-01" in fired(missing, "info")
    bot_wall = healthy(other=ok_http("https://example.com/", 403))
    assert fired(bot_wall) == set()


def test_blocked_vantage_point_never_blames_the_domain():
    obs = healthy(delegation=Delegation(parent_ns=NS, vantage_blocked=True, ds_present=False))
    assert fired(obs) == set()


# --- Registration ----------------------------------------------------------------

def test_reg01_client_hold():
    obs = healthy(registration=Registration(domain="example.com", statuses=["client hold"], expires=NOW + timedelta(days=100)))
    d = next(d for d in rules.run(obs) if d.id == "REG-01")
    assert "hold" in d.title and d.level == "error"


def test_reg01_expiring_soon_is_warning():
    obs = healthy(registration=Registration(domain="example.com", expires=NOW + timedelta(days=12)))
    assert [d.level for d in rules.run(obs) if d.id == "REG-01"] == ["warning"]


def test_reg01_not_registered():
    obs = healthy(delegation=Delegation(parent_nxdomain=True), dns=DNSRecords(status="nxdomain"))
    ids = fired(obs)
    assert "REG-01" in ids and "DNS-01" not in ids
