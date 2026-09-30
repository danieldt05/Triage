import pytest

from triage.lookup.providers import cdn, dns_provider, matches_expected
from triage.lookup.target import parse_input


@pytest.mark.parametrize("raw,host,url", [
    ("example.com", "example.com", "https://example.com/"),
    ("https://WWW.Example.com/checkout?x=1", "www.example.com", "https://www.example.com/checkout?x=1"),
    ("http://example.com.", "example.com", "http://example.com/"),
    ("bücher.de", "xn--bcher-kva.de", "https://xn--bcher-kva.de/"),
])
def test_parse_input(raw, host, url):
    assert parse_input(raw) == (host, url)


@pytest.mark.parametrize("raw", ["", "ftp://example.com", "1.2.3.4", "localhost", "https://[::1]/"])
def test_parse_input_rejects(raw):
    with pytest.raises(ValueError):
        parse_input(raw)


def test_providers():
    assert dns_provider(["ns-12.awsdns-01.org"]) == "Amazon Route 53"
    assert dns_provider(["pdns1.registrar-servers.com"]) == "Namecheap"
    assert dns_provider(["ns1.unknownhost.example"]) is None
    assert cdn({"x-amz-cf-id": "abc"}) == "Amazon CloudFront"
    assert cdn({"x-served-by": "cache-lhr123"}) == "Fastly"
    assert cdn({"server": "nginx"}) is None
    assert matches_expected("ns1.a.example, ns2.a.example", ["NS1.a.example.", "ns2.a.example"]) is True
    assert matches_expected("Somewhere", ["ns1.unknownhost.example"]) is None
