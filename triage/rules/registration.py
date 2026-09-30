from __future__ import annotations

from datetime import timedelta

from triage.model import Observation
from triage.rules import Diagnosis, rule

# RDAP status values that take a domain offline (RFC 8056 mapping of EPP statuses).
OFFLINE = {"clienthold": "put on hold by the registrar", "serverhold": "put on hold by the registry",
           "redemptionperiod": "expired and in its redemption period", "pendingdelete": "about to be deleted"}


@rule("REG-01")
def registration_problem(obs: Observation) -> Diagnosis | None:
    reg, now = obs.registration, obs.checked_at
    registrar = reg.registrar or "the registrar"

    if obs.delegation.parent_nxdomain or reg.not_found:
        return Diagnosis(
            id="REG-01", level="error", step="registration",
            title=f"{obs.apex} isn't registered",
            summary="The registry has no record of this domain. It may have expired and been deleted, or never been registered.",
            evidence=[("Registry", "domain not found")],
            fix=["Check the spelling of the domain.", "If it was the customer's, check whether it can still be renewed or re-registered."],
            reply=f"{obs.apex} isn't currently registered, so it can't point anywhere. It may have expired; please check with your registrar.",
            confidence_reason="The registry itself says the name doesn't exist.",
        )

    held = [OFFLINE[k] for s in reg.statuses if (k := s.replace(" ", "").lower()) in OFFLINE]
    if held:
        return Diagnosis(
            id="REG-01", level="error", step="registration",
            title=f"The domain is {held[0]}",
            summary="While a domain is on hold, the registry stops publishing its nameservers, so nothing on it works: website or email.",
            evidence=[("Registry status", ", ".join(reg.statuses))],
            fix=[f"Contact {registrar}. Holds usually follow an unpaid renewal or an unverified contact email."],
            reply=(f"Your domain has been placed on hold ({held[0]}), which takes the website and email offline. "
                   f"Please contact {registrar}; it's usually resolved by renewing or verifying your contact email."),
            confidence_reason="Read from the registry's status codes.",
        )

    if reg.expires and reg.expires < now:
        return Diagnosis(
            id="REG-01", level="error", step="registration",
            title=f"The domain registration expired on {reg.expires:%d %b %Y}",
            summary="Once the registrar's grace period ends, the domain stops working and can be lost.",
            evidence=[("Registry", f"expiry {reg.expires:%Y-%m-%d}")],
            fix=[f"Renew the domain at {registrar} as soon as possible."],
            reply=f"Your domain expired on {reg.expires:%d %B %Y}. Please renew it with {registrar} as soon as possible.",
            confidence_reason="Read from the registry's expiry date.",
        )

    if reg.expires and reg.expires - now < timedelta(days=30):
        days = (reg.expires - now).days
        return Diagnosis(
            id="REG-01", level="warning", step="registration",
            title=f"The domain expires in {days} days",
            summary="If it isn't renewed, the website and email will stop working.",
            evidence=[("Registry", f"expiry {reg.expires:%Y-%m-%d}")],
            fix=[f"Renew at {registrar}, and turn on auto-renew."],
            reply=f"Heads up: your domain expires in {days} days. Renewing it with {registrar} will avoid an outage.",
            confidence_reason="Read from the registry's expiry date.",
        )
    return None
