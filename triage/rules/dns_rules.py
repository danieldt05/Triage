from __future__ import annotations

from triage.model import Observation
from triage.rules import Diagnosis, rule


def _other_works(obs: Observation) -> bool:
    return bool(obs.other and obs.other.ok and obs.other.status is not None and obs.other.status < 500)


@rule("DNS-01")
def name_does_not_exist(obs: Observation) -> Diagnosis | None:
    if obs.dns.status != "nxdomain" or obs.delegation.parent_nxdomain:
        return None  # an unregistered domain is REG-01's job
    evidence = [("Resolvers", f"{obs.host}: NXDOMAIN (no such name)")]
    fix = []
    if _other_works(obs):
        evidence.append(("Counterpart", f"{obs.other_host} resolves and loads"))
        fix.append(f"Add a DNS record for {obs.host} (for www, usually a CNAME to {obs.apex}).")
        fix.append(f"Meanwhile the customer can use {obs.other_host}.")
    else:
        fix.append(f"Add an A, AAAA or CNAME record for {obs.host} at the DNS provider.")
    return Diagnosis(
        id="DNS-01", level="error", step="dns",
        title=f"{obs.host} doesn't exist in DNS",
        summary="There's no DNS record for this name at all, so browsers can't find the site.",
        evidence=evidence, fix=fix,
        reply=(f"There's currently no DNS record for {obs.host}, so browsers can't find it. "
               "Adding a record for it at your DNS provider will fix this."),
        confidence_reason="Resolvers returned NXDOMAIN for the name.",
    )


@rule("DNS-02")
def no_address(obs: Observation) -> Diagnosis | None:
    if obs.dns.status != "nodata" or obs.dns.aaaa:
        return None
    chain = obs.dns.cname_chain
    if chain:
        return Diagnosis(
            id="DNS-02", level="error", step="dns",
            title=f"{obs.host} points to a name that has no address",
            summary=(f"{obs.host} is an alias (CNAME) for {chain[-1]}, but that name returns no address. "
                     "This usually means the service it pointed to was removed or renamed."),
            evidence=[("CNAME chain", " → ".join([obs.host, *chain])), ("Resolvers", f"{chain[-1]}: no A or AAAA record")],
            fix=["Update the CNAME to the service's current hostname, or remove it if the service is gone.",
                 "If the target is a third-party service that no longer exists, remove the record promptly: "
                 "someone else could claim that name and serve content on this subdomain."],
            reply=(f"{obs.host} points to a service address ({chain[-1]}) that no longer exists, so it can't load. "
                   "The DNS record needs updating to the service's current address."),
            confidence_reason="Name exists, but the end of its alias chain has no address.",
        )
    return Diagnosis(
        id="DNS-02", level="error", step="dns",
        title=f"{obs.host} has no address records",
        summary="The name exists but has no A or AAAA record, so there's no server to connect to.",
        evidence=[("Resolvers", f"{obs.host}: no A or AAAA record")],
        fix=[f"Add an A record (IPv4) or CNAME for {obs.host} pointing at the web host."],
        reply=f"{obs.host} exists in DNS but isn't pointed at any server yet. Adding an address record will fix this.",
        confidence_reason="Resolvers answered with no address for the name.",
    )


@rule("DNS-03")
def resolution_fails(obs: Observation) -> Diagnosis | None:
    if obs.dns.status not in ("servfail", "timeout") or obs.delegation.dnssec_broken:
        return None  # broken DNSSEC is the more specific explanation (DNS-05)
    failed = "fail (SERVFAIL)" if obs.dns.status == "servfail" else "time out"
    return Diagnosis(
        id="DNS-03", level="error", step="nameservers",
        title=f"DNS lookups for {obs.host} {failed}",
        summary=("Resolvers can't get an answer from this domain's nameservers, so the site is unreachable "
                 "for everyone whose resolver fails."),
        evidence=[("Resolvers", f"{obs.host}: {obs.dns.status}"),
                  ("Delegated to", ", ".join(obs.delegation.parent_ns) or "unknown")],
        fix=["Check the nameservers listed at the registrar are correct and online (see the nameserver findings)."],
        reply=("Your domain's DNS servers aren't answering at the moment, so browsers can't look up the site. "
               "This needs fixing at your DNS provider or registrar."),
        confidence="Medium", confidence_reason="A transient network issue can also cause this; re-check to confirm.",
    )


@rule("DNS-07")
def resolvers_disagree(obs: Observation) -> Diagnosis | None:
    answered = [r for r in obs.resolvers if r.status == "ok"]
    ns_sets = {tuple(r.ns) for r in answered if r.ns}
    if len(ns_sets) > 1:
        return Diagnosis(
            id="DNS-07", level="warning", step="nameservers",
            title="Public resolvers disagree about the nameservers",
            summary=("Some resolvers still have the old nameservers cached. Visitors using those resolvers "
                     "reach the old DNS setup until the cache expires."),
            evidence=[(f"{r.name} {r.ip}", ", ".join(r.ns) or "no answer") for r in obs.resolvers],
            fix=["Usually no action: nameserver changes can take up to 48 hours to reach every resolver.",
                 "If it persists beyond that, re-check the nameservers set at the registrar."],
            reply=("Your recent nameserver change is still spreading across the internet. Most visitors already "
                   "see the new setup; everyone will within 48 hours at most."),
            confidence_reason="Resolvers returned different nameserver sets for the same domain.",
        )
    a_sets = [set(r.a) for r in answered if r.a]
    if len(a_sets) > 1 and not set.intersection(*a_sets):
        return Diagnosis(
            id="DNS-07", level="info", step="dns",
            title="Resolvers return completely different addresses",
            summary=("That's normal for CDNs and geo-routed sites, but it can also mean an address change is "
                     "still spreading. Worth knowing if the customer sees an old version of the site."),
            evidence=[(f"{r.name} {r.ip}", ", ".join(r.a) or "no answer") for r in obs.resolvers],
            fix=["If the customer changed the address recently, wait for the record's TTL to pass "
                 f"({obs.dns.a_ttl} s)." if obs.dns.a_ttl else "Re-check after the record's TTL has passed."],
            confidence="Low", confidence_reason="CDN and geo-DNS routing cause the same pattern legitimately.",
        )
    return None
