from __future__ import annotations

from triage.lookup.providers import dns_provider, matches_expected
from triage.model import Observation
from triage.rules import Diagnosis, rule


@rule("DEL-01")
def not_delegated_to_expected(obs: Observation) -> Diagnosis | None:
    d = obs.delegation
    if not obs.expected or not d.parent_ns:
        return None
    if matches_expected(obs.expected, d.parent_ns) is not False:
        return None  # matches, or we can't tell: stay silent

    current = dns_provider(d.parent_ns) or d.parent_ns[0]
    evidence = [
        (f".{d.parent_zone} registry" if d.parent_zone else "Registry", ", ".join(d.parent_ns)),
        ("Expected", obs.expected),
    ]
    signals = 1
    agreeing = [r for r in obs.resolvers if r.ns and set(r.ns) == set(d.parent_ns)]
    if len(agreeing) >= 3:
        signals += 1
        evidence.append((f"Resolvers {len(agreeing)}/{len(obs.resolvers)}",
                         "return the same nameservers, so this isn't just propagation delay"))
    registrar = obs.registration.registrar or "the registrar"
    return Diagnosis(
        id="DEL-01", level="error", step="nameservers",
        title=f"The domain is still delegated to {current}, not {obs.expected}",
        summary=(f"The registry sends visitors to {current}'s nameservers, so DNS changes made at "
                 f"{obs.expected} aren't being used."),
        evidence=evidence,
        fix=[f"Log in at {registrar}.",
             f"Replace the nameservers with the ones shown in the {obs.expected} account.",
             "Re-check here. Nameserver changes can take up to 48 hours to reach every resolver; most update within a few hours."],
        reply=(f"Your domain's nameservers at {registrar} still point to {current}, so the DNS changes you made at "
               f"{obs.expected} aren't being used yet. Please update the nameservers in your {registrar} account to the "
               f"ones {obs.expected} gave you. Most visitors will see the change within a few hours; it can take up to 48 hours everywhere."),
        confidence="High" if signals >= 2 else "Medium",
        confidence_reason=f"{signals} independent signal{'s' if signals > 1 else ''}: registry delegation"
                          + (" and resolver answers agree." if signals > 1 else " only; resolvers weren't conclusive."),
    )


@rule("DEL-02")
def registry_and_zone_disagree(obs: Observation) -> Diagnosis | None:
    d = obs.delegation
    if d.vantage_blocked or not d.parent_ns or not d.child_ns or set(d.parent_ns) == set(d.child_ns):
        return None
    return Diagnosis(
        id="DEL-02", level="warning", step="nameservers",
        title="The registry and the DNS zone list different nameservers",
        summary=("Resolvers may use either list, so changes can appear to work for some people and not others. "
                 "This often happens midway through moving DNS providers."),
        evidence=[("Registry", ", ".join(d.parent_ns)), ("Zone's own NS records", ", ".join(d.child_ns))],
        fix=["Make the NS records inside the zone match the nameservers set at the registrar."],
        reply=("Your domain's nameserver settings are inconsistent between your registrar and your DNS provider, which can "
               "make changes appear for some visitors but not others. Aligning them will fix this."),
        confidence_reason="Directly compared the registry's delegation with the zone's NS records.",
    )


@rule("DEL-03")
def lame_nameservers(obs: Observation) -> Diagnosis | None:
    d = obs.delegation
    if d.vantage_blocked or not d.lame or not d.parent_ns:
        return None
    all_bad = len(d.lame) >= len(d.parent_ns)
    return Diagnosis(
        id="DEL-03", level="error" if all_bad else "warning", step="nameservers",
        title=("None of the domain's nameservers answer for it" if all_bad
               else f"{len(d.lame)} of {len(d.parent_ns)} nameservers don't answer for this domain"),
        summary=("Resolvers that try a broken nameserver get failures or slow lookups. "
                 + ("With every nameserver failing, the domain can't be resolved." if all_bad
                    else "The site mostly works, but some lookups are slow or fail.")),
        evidence=[(ns, reason) for ns, reason in d.lame],
        fix=["At the registrar, remove nameservers that don't host this domain.",
             "Or add the domain to that DNS provider so it answers."],
        reply=("Some of the DNS servers your domain points to aren't set up to answer for it, which makes the site "
               "intermittently slow or unreachable. Your registrar settings need updating."),
        confidence_reason="Asked each delegated nameserver directly for an authoritative answer.",
    )


@rule("DNS-05")
def broken_dnssec(obs: Observation) -> Diagnosis | None:
    if not obs.delegation.dnssec_broken:
        return None
    return Diagnosis(
        id="DNS-05", level="error", step="nameservers",
        title="DNSSEC is broken, so validating resolvers refuse to answer",
        summary=("The registry holds a DNSSEC (DS) record, but the nameservers' signatures don't match it. "
                 "Resolvers that validate DNSSEC return an error, so the site fails for a large share of visitors. "
                 "This is common right after moving DNS providers."),
        evidence=[("Registry", "DS record present"),
                  ("Validating resolver", "SERVFAIL"),
                  ("Same query, validation off", "answers normally")],
        fix=["Remove the DS record at the registrar, or",
             "enable DNSSEC at the current DNS provider and publish its DS record at the registrar instead."],
        reply=("Your domain has a DNSSEC security setting left over at your registrar that no longer matches your DNS "
               "provider, so many internet providers refuse to look the site up. Removing or updating that DS record "
               "at your registrar will fix it."),
        confidence_reason="A validating resolver fails and succeeds only with validation disabled.",
    )
