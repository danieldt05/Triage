"""Best-effort provider identification from public, observable signals:
nameserver hostnames and HTTP response headers. Nothing vendor-internal.

Unknown providers are fine: the UI shows the nameserver name instead, and no
rule depends on a provider being recognised.
"""

from __future__ import annotations

# (substring of nameserver hostname, provider)
DNS_PROVIDERS = [
    ("awsdns-", "Amazon Route 53"),
    (".ns.cloudflare.com", "Cloudflare"),
    ("domaincontrol.com", "GoDaddy"),
    ("googledomains.com", "Google Cloud DNS"),
    ("azure-dns.", "Azure DNS"),
    ("nsone.net", "NS1"),
    ("dnsimple", "DNSimple"),
    ("digitalocean.com", "DigitalOcean"),
    ("registrar-servers.com", "Namecheap"),
    ("akam.net", "Akamai"),
    ("ultradns.", "UltraDNS"),
    ("dynect.net", "Oracle Dyn"),
    ("vercel-dns.com", "Vercel"),
    ("ovh.net", "OVHcloud"),
    ("gandi.net", "Gandi"),
    ("porkbun.com", "Porkbun"),
    ("linode.com", "Linode"),
    ("hetzner.", "Hetzner"),
    ("ui-dns.", "IONOS"),
    ("wixdns.net", "Wix"),
    ("squarespacedns.com", "Squarespace"),
    ("dns.he.net", "Hurricane Electric"),
]

# (header name, required substring of the value or None, provider)
CDN_HEADERS = [
    ("cf-ray", None, "Cloudflare"),
    ("x-amz-cf-id", None, "Amazon CloudFront"),
    ("x-fastly-request-id", None, "Fastly"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-vercel-id", None, "Vercel"),
    ("x-nf-request-id", None, "Netlify"),
    ("x-azure-ref", None, "Azure Front Door"),
    ("x-sucuri-id", None, "Sucuri"),
    ("x-iinfo", None, "Imperva"),
    ("server", "akamaighost", "Akamai"),
    ("server", "bunnycdn", "Bunny CDN"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "netlify", "Netlify"),
    ("via", "google", "Google Cloud load balancer"),
]


def dns_provider(nameservers: list[str]) -> str | None:
    names = [n.lower() for n in nameservers]
    for needle, provider in DNS_PROVIDERS:
        if any(needle in n for n in names):
            return provider
    return None


def cdn(headers: dict[str, str]) -> str | None:
    for name, needle, provider in CDN_HEADERS:
        value = headers.get(name)
        if value is not None and (needle is None or needle in value.lower()):
            return provider
    return None


ALIASES = {"aws": "amazon route 53", "route53": "amazon route 53", "gcp": "google cloud dns",
           "google": "google cloud dns", "azure": "azure dns", "do": "digitalocean"}


def matches_expected(expected: str, nameservers: list[str]) -> bool | None:
    """`expected` is either a provider name ("Route 53") or nameserver names
    ("ns1.host.net, ns2.host.net").

    Returns True/False, or None when we can't tell (the delegated nameservers
    belong to a provider we don't recognise). A rule must not fire on None:
    "we don't know" is not evidence of a mismatch.
    """
    expected = expected.strip().lower()
    names = [n.lower().rstrip(".") for n in nameservers]
    if not expected or not names:
        return None
    if "." in expected:
        wanted = {e.strip().rstrip(".") for e in expected.replace(",", " ").split() if e.strip()}
        return wanted <= set(names)
    expected = ALIASES.get(expected, expected)
    provider = (dns_provider(names) or "").lower()
    if not provider:
        return None
    return expected in provider or provider in expected
