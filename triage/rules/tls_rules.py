from __future__ import annotations

from datetime import timedelta

from triage.lookup import tls as T
from triage.model import Observation
from triage.rules import Diagnosis, rule

WARNING_REPLY = ("Visitors see a security warning instead of your site, and apps or other services that connect to it "
                 "refuse to. ")


@rule("TLS-01")
def certificate_dates(obs: Observation) -> Diagnosis | None:
    t = obs.tls
    if not t or not t.cert:
        return None
    c, now = t.cert, obs.checked_at
    if now > c.not_after:
        days = (now - c.not_after).days
        return Diagnosis(
            id="TLS-01", level="error", step="tls",
            title=f"The SSL certificate expired {days} day{'s' if days != 1 else ''} ago",
            summary="Browsers show a full-page security warning and most apps and APIs refuse to connect.",
            evidence=[("Certificate", f"valid until {c.not_after:%d %b %Y}"), ("Issuer", c.issuer or "unknown")],
            fix=["Renew the certificate.",
                 "If it's meant to renew automatically (e.g. an ACME client like certbot), find out why renewal stopped."],
            reply=WARNING_REPLY + f"This is because the site's security certificate expired on {c.not_after:%d %B %Y}. Renewing it will fix this.",
            confidence_reason="Read directly from the certificate.",
        )
    if now < c.not_before:
        return Diagnosis(
            id="TLS-01", level="error", step="tls",
            title="The SSL certificate isn't valid yet",
            summary="Its start date is in the future, so clients reject it. Usually a wrong server clock or a mis-issued certificate.",
            evidence=[("Certificate", f"valid from {c.not_before:%d %b %Y %H:%M} UTC")],
            fix=["Check the server's clock (NTP) and the certificate's validity dates."],
            reply=WARNING_REPLY + "The site's security certificate isn't valid yet, which usually points to a server clock problem.",
            confidence_reason="Read directly from the certificate.",
        )
    # Relative to the certificate's lifetime: ACME clients renew with about a
    # third remaining, and certificate lifetimes are shrinking industry-wide.
    lifetime, remaining = c.not_after - c.not_before, c.not_after - now
    if remaining < min(lifetime * 0.10, timedelta(days=7)):
        level, title = "warning", f"The SSL certificate expires in {remaining.days} days"
    elif remaining < min(lifetime / 3, timedelta(days=30)):
        level, title = "info", f"The SSL certificate expires in {remaining.days} days"
    else:
        return None
    return Diagnosis(
        id="TLS-01", level=level, step="tls", title=title,
        summary="It's past the point where automatic renewal normally happens, so renewal may be failing.",
        evidence=[("Certificate", f"{lifetime.days}-day certificate, valid until {c.not_after:%d %b %Y}")],
        fix=["Renew now, and check the automatic renewal job."],
        confidence_reason="Read directly from the certificate.",
    )


@rule("TLS-02")
def verification(obs: Observation) -> Diagnosis | None:
    t = obs.tls
    if not t or t.verified or t.verify_code is None:
        return None
    code, c = t.verify_code, t.cert
    if code in (T.ERR_EXPIRED, T.ERR_NOT_YET_VALID) and c and not (c.not_before <= obs.checked_at <= c.not_after):
        return None  # TLS-01 already explains it
    ev = [("OpenSSL", f"{t.verify_message} (code {code})")]

    if code == T.ERR_HOSTNAME_MISMATCH:
        names = ", ".join(c.sans[:6]) if c and c.sans else "other names"
        return Diagnosis(
            id="TLS-02", level="error", step="tls",
            title=f"The SSL certificate doesn't cover {obs.host}",
            summary=f"The server presents a certificate for {names}, so browsers warn that the site may be an impostor.",
            evidence=ev + [("Certificate covers", names)],
            fix=[f"Issue a certificate that includes {obs.host}.",
                 "If the name was just pointed at a new host, the old host may still be answering (check the DNS findings)."],
            reply=WARNING_REPLY + f"The site's security certificate doesn't include {obs.host}. A certificate covering that name will fix this.",
            confidence_reason="OpenSSL hostname verification failed.",
        )
    if code == T.ERR_SELF_SIGNED_LEAF or (c and c.self_signed):
        return Diagnosis(
            id="TLS-02", level="error", step="tls",
            title="The SSL certificate is self-signed",
            summary="No trusted authority vouches for it, so every browser shows a warning.",
            evidence=ev, fix=["Install a certificate from a public certificate authority (free ones are available)."],
            reply=WARNING_REPLY + "The site uses a self-signed certificate, which browsers don't trust.",
            confidence_reason="Certificate issuer equals its subject.",
        )
    if code in (T.ERR_NO_LOCAL_ISSUER, T.ERR_CANT_VERIFY_LEAF) and t.chain_length == 1:
        return Diagnosis(
            id="TLS-02", level="warning", step="tls",
            title="The server doesn't send its intermediate certificate",
            summary=("Many desktop browsers fill the gap themselves, so the site may look fine to the customer, "
                     "but apps, APIs, command-line tools and some phones fail to connect."),
            evidence=ev + [("Certificates sent", "1 (the site's own only)")],
            fix=["Configure the server with the full chain file (often named fullchain.pem) instead of the certificate alone."],
            reply=("Your site works in most browsers, but its security certificate is installed without the intermediate "
                   "certificate, so some apps and devices can't connect. Your host can fix this by installing the full chain."),
            confidence_reason="Server sent only its own certificate.",
        )
    if code in (T.ERR_SELF_SIGNED_IN_CHAIN, T.ERR_NO_LOCAL_ISSUER, T.ERR_CANT_VERIFY_LEAF):
        note = "" if t.chain_length is not None else " (It may be a missing intermediate certificate; this server can't tell the two apart.)"
        return Diagnosis(
            id="TLS-02", level="error", step="tls",
            title="The SSL certificate isn't trusted",
            summary="Its chain doesn't lead to a certificate authority that browsers trust." + note,
            evidence=ev, fix=["Use a certificate from a public certificate authority and install the full chain."],
            reply=WARNING_REPLY + "The site's security certificate isn't from a trusted authority or is installed incompletely.",
            confidence="High" if t.chain_length is not None else "Medium",
            confidence_reason="OpenSSL chain verification failed.",
        )
    return Diagnosis(
        id="TLS-02", level="error", step="tls",
        title="The SSL certificate failed verification",
        summary=f"OpenSSL rejected it: {t.verify_message}.",
        evidence=ev, fix=["Investigate the specific error above with the certificate provider."],
        reply=WARNING_REPLY + "The site's security certificate has a problem that needs fixing.",
        confidence_reason="OpenSSL verification failed.",
    )
