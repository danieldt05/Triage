"""Plain data describing what the lookups observed.

Nothing in this module makes a judgement. Lookups fill these objects in; rules
(triage/rules) read them and decide what's wrong. Keeping the two apart means
every rule can be unit-tested with a hand-built Observation and no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DNSRecords:
    status: str = "ok"          # result of the A lookup: ok | nodata | nxdomain | servfail | timeout
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)  # host -> ... -> canonical name
    a_ttl: int | None = None
    ns: list[str] = field(default_factory=list)            # NS as served to resolvers (apex)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)
    soa: str | None = None


@dataclass
class Delegation:
    parent_zone: str | None = None
    parent_ns: list[str] = field(default_factory=list)   # what the registry (parent zone) delegates to
    child_ns: list[str] = field(default_factory=list)    # what the zone's own nameservers say
    lame: list[tuple[str, str]] = field(default_factory=list)  # (nameserver, reason)
    parent_nxdomain: bool = False                          # registry says the domain doesn't exist
    ds_present: bool | None = None
    dnssec_broken: bool | None = None                      # DS exists but validation fails
    vantage_blocked: bool = False                          # couldn't query nameservers directly from here
    error: str | None = None


@dataclass
class ResolverAnswer:
    name: str
    ip: str
    a: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    status: str = "ok"


@dataclass
class Hop:
    url: str
    status: int
    location: str | None = None


@dataclass
class HTTPResult:
    start_url: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int | None = None
    loop: bool = False
    cert_error_ignored: bool = False
    blocked: bool = False       # target resolved to a private address; request refused
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.blocked and not self.loop and self.status is not None


@dataclass
class Connectivity:
    family: str                 # "IPv4" | "IPv6"
    address: str | None = None
    ok: bool = False
    ms: int | None = None
    error: str | None = None
    inconclusive: bool = False  # e.g. this server has no IPv6, so we can't judge


@dataclass
class CertInfo:
    subject_cn: str | None
    issuer: str | None
    sans: list[str]
    not_before: datetime
    not_after: datetime
    self_signed: bool


@dataclass
class TLSResult:
    host: str
    verified: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    version: str | None = None
    cert: CertInfo | None = None
    chain_length: int | None = None
    error: str | None = None


@dataclass
class Registration:
    domain: str | None = None
    registrar: str | None = None
    created: datetime | None = None
    expires: datetime | None = None
    updated: datetime | None = None
    statuses: list[str] = field(default_factory=list)
    not_found: bool = False
    error: str | None = None


@dataclass
class Observation:
    host: str
    url: str
    apex: str
    other_host: str | None                 # the www / non-www counterpart, if any
    expected: str | None                    # "DNS should be at" input, optional
    checked_at: datetime
    dns: DNSRecords = field(default_factory=DNSRecords)
    delegation: Delegation = field(default_factory=Delegation)
    resolvers: list[ResolverAnswer] = field(default_factory=list)
    authoritative_a: list[str] | None = None
    https: HTTPResult | None = None
    http: HTTPResult | None = None           # plain http:// request, to check the HTTPS redirect
    other: HTTPResult | None = None          # the counterpart host over https
    tls: TLSResult | None = None
    ipv4: Connectivity | None = None
    ipv6: Connectivity | None = None
    registration: Registration = field(default_factory=Registration)
    dns_provider: str | None = None
    cdn: str | None = None
    duration_ms: int = 0
