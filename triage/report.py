"""Shape an Observation plus its Diagnoses into the JSON the web page renders."""

from __future__ import annotations

from dataclasses import asdict

from triage.model import Observation
from triage.rules import Diagnosis

TONE = {"error": "err", "warning": "warn", "info": "ok"}


def build(obs: Observation, diags: list[Diagnosis]) -> dict:
    return {
        "host": obs.host,
        "url": obs.url,
        "apex": obs.apex,
        "other_host": obs.other_host,
        "expected": obs.expected,
        "checked_at": obs.checked_at.isoformat(),
        "duration_ms": obs.duration_ms,
        "verdict": _verdict(obs, diags),
        "path": _path(obs, diags),
        "diagnoses": [asdict(d) for d in diags],
        "healthy": _healthy(obs, diags),
        "reply": _reply(obs, diags),
        "raw": _raw(obs),
        "facts": _facts(obs),
    }


def _verdict(obs: Observation, diags: list[Diagnosis]) -> dict:
    problems = [d for d in diags if d.level in ("error", "warning")]
    if not problems:
        return {"tone": "ok", "label": "Looks healthy", "headline": f"No problems found with {obs.host}",
                "summary": ("DNS, the certificate and the web server all respond normally from here. If the customer "
                            "still has a problem, it's probably local: their browser cache, DNS resolver or network.")}
    confident = [d for d in problems if d.confidence != "Low"]
    top = (confident or problems)[0]
    if not confident:
        return {"tone": "warn", "label": "Check manually", "headline": top.title, "summary": top.summary}
    return {"tone": TONE[top.level], "label": "Broken" if top.level == "error" else "Needs attention",
            "headline": top.title, "summary": top.summary}


def _worst(diags: list[Diagnosis], steps: set[str]) -> str | None:
    levels = [d.level for d in diags if d.step in steps and d.level in ("error", "warning")]
    return "err" if "error" in levels else "warn" if "warning" in levels else None


def _path(obs: Observation, diags: list[Diagnosis]) -> list[dict]:
    resolves = bool(obs.dns.a or obs.dns.aaaa)
    d = obs.delegation

    name = {"step": "Name lookup", "name": obs.host,
            "value": ", ".join((obs.dns.a or obs.dns.aaaa)[:2]) or obs.dns.status.upper(),
            "tone": _worst(diags, {"dns"}) or ("ok" if resolves else "err")}
    name["status"] = {"ok": "Resolves", "warn": "Partly working", "err": "Fails"}[name["tone"]]

    ns_list = d.parent_ns or obs.dns.ns
    ns = {"step": "Nameservers", "name": obs.dns_provider or ("Unrecognised provider" if ns_list else "None found"),
          "value": ns_list[0] if ns_list else "unknown",
          "tone": _worst(diags, {"nameservers", "registration"}) or ("idle" if d.vantage_blocked or not ns_list else "ok")}
    ns["status"] = {"ok": "Answering", "warn": "Inconsistent", "err": "Problem",
                    "idle": "Not verified" if d.vantage_blocked else "Unknown"}[ns["tone"]]

    reached = resolves and obs.https is not None and not obs.https.blocked
    edge = {"step": "CDN or proxy", "name": obs.cdn or "None detected",
            "value": "in front of the server" if obs.cdn else "direct to server",
            "tone": "ok" if obs.cdn else "idle", "status": "Detected" if obs.cdn else "Not used"}

    t = obs.tls
    tls_tone = _worst(diags, {"tls"}) or ("ok" if t and t.verified else "idle")
    tls = {"step": "Certificate", "name": (t.cert.issuer.split(" / ")[0] if t and t.cert and t.cert.issuer else "No certificate"),
           "value": (f"until {t.cert.not_after:%d %b %Y}" if t and t.cert else (t.error if t and t.error else "not checked")),
           "tone": tls_tone, "status": {"ok": "Valid", "warn": "Warning", "err": "Invalid", "idle": "Not checked"}[tls_tone]}

    r = obs.https
    srv_tone = _worst(diags, {"server"}) or ("ok" if r and r.status and r.status < 400 else "idle")
    server = {"step": "Web server", "name": (r.headers.get("server") if r and r.headers.get("server") else "Server"),
              "value": (f"HTTP {r.status} · {r.elapsed_ms} ms" if r and r.status else (r.error if r and r.error else "no response")),
              "tone": srv_tone, "status": {"ok": "Responding", "warn": "Warning", "err": "Failing", "idle": "No response"}[srv_tone]}

    steps = [name, ns, edge, tls, server]
    if not reached:
        for s in steps[2:]:
            s.update(tone="idle", status="Not reached", value="lookup stopped earlier", name=s["step"])
    return steps


def _healthy(obs: Observation, diags: list[Diagnosis]) -> list[dict]:
    fired = {d.id for d in diags if d.level in ("error", "warning")}
    out = []
    def add(name, value): out.append({"name": name, "value": value})

    if (obs.dns.a or obs.dns.aaaa) and not fired & {"DNS-01", "DNS-02", "DNS-03"}:
        add("DNS", f"{len(obs.dns.a)} IPv4, {len(obs.dns.aaaa)} IPv6 address{'es' if len(obs.dns.a) + len(obs.dns.aaaa) != 1 else ''}")
    d = obs.delegation
    if d.parent_ns and not d.lame and not d.vantage_blocked and not fired & {"DEL-01", "DEL-02", "DEL-03"}:
        add("Nameservers", f"{len(d.parent_ns)} delegated, all answering")
    if obs.dns.status == "ok" and d.ds_present is not None and not d.dnssec_broken:
        add("DNSSEC", "Signed and valid" if d.ds_present else "Not enabled")
    answered = [r for r in obs.resolvers if r.status == "ok"]
    if answered and "DNS-07" not in fired:
        add("Propagation", f"{len(answered)} public resolvers agree")
    if obs.tls and obs.tls.verified and obs.tls.cert and not fired & {"TLS-01", "TLS-02"}:
        add("Certificate", f"Valid, {(obs.tls.cert.not_after - obs.checked_at).days} days left")
    if obs.http and (obs.http.final_url or "").startswith("https://"):
        add("HTTPS redirect", "http:// redirects to https://")
    if obs.https and obs.https.status and obs.https.status < 400 and not fired & {"HTTP-01", "NET-02"}:
        add("Web server", f"HTTP {obs.https.status} in {obs.https.elapsed_ms} ms")
    if obs.ipv6 and obs.ipv6.ok:
        add("IPv6", f"Reachable in {obs.ipv6.ms} ms")
    if obs.other and obs.other.ok and obs.other.status and obs.other.status < 400 and "HOST-01" not in fired:
        add(obs.other_host, "Also loads")
    reg = obs.registration
    if reg.expires and "REG-01" not in fired:
        add("Registration", f"Expires {reg.expires:%d %b %Y}")
    return out


def _reply(obs: Observation, diags: list[Diagnosis]) -> str:
    parts = [d.reply for d in diags if d.reply and d.level in ("error", "warning")]
    if parts:
        return " ".join(dict.fromkeys(parts))  # de-duplicate, keep order
    return (f"We checked {obs.host} from outside your network: DNS, the security certificate and the web server all "
            "respond normally. The problem may be local to your device or network. Could you try a private browser "
            "window, or load the site on mobile data, and let us know what you see?")


def _rows(pairs) -> list[dict]:
    return [{"k": k, "v": v} for k, v in pairs if v not in (None, "", [])]


def _raw(obs: Observation) -> dict:
    h, apex, d, rec = obs.host, obs.apex, obs.delegation, obs.dns
    tld_server = "a.gtld-servers.net" if (d.parent_zone or "") in ("com", "net") else f"$(dig +short {d.parent_zone or 'TLD'} NS | head -1)"
    raw = {
        "dns": {
            "rows": _rows([
                ("A", ", ".join(rec.a) + (f"  (TTL {rec.a_ttl})" if rec.a and rec.a_ttl else "") or f"none ({rec.status})"),
                ("AAAA", ", ".join(rec.aaaa) or "none"),
                ("CNAME chain", " → ".join([h, *rec.cname_chain]) if rec.cname_chain else None),
                ("NS", "\n".join(rec.ns)),
                ("MX", "\n".join(rec.mx) or "none"),
                ("TXT", "\n".join(rec.txt)),
                ("DMARC", "\n".join(rec.dmarc) or "none"),
                ("CAA", "\n".join(rec.caa) or "none"),
                ("SOA", rec.soa),
            ]),
            "commands": [f"dig +short {h} A", f"dig +short {h} AAAA", f"dig +short {h} CNAME",
                         f"dig +short {apex} NS", f"dig +short {apex} MX", f"dig +short {apex} TXT",
                         f"dig +short _dmarc.{apex} TXT"],
        },
        "delegation": {
            "rows": _rows([
                ("Registry says", "\n".join(d.parent_ns) or (d.error or "unknown")),
                ("Zone says", "\n".join(d.child_ns) or ("not checked: " + (d.error or "") if d.vantage_blocked else "no authoritative answer")),
                ("Not answering", "\n".join(f"{ns}: {why}" for ns, why in d.lame) or "none"),
                ("DS record", {True: "present", False: "none", None: "unknown"}[d.ds_present]),
                ("DNSSEC", {True: "broken", False: "valid", None: "not applicable"}[d.dnssec_broken]),
                ("Provider", obs.dns_provider or "not recognised"),
            ]),
            "commands": [f"dig @{tld_server} {apex} NS +norecurse +noall +authority",
                         f"dig @{(d.parent_ns or ['NAMESERVER'])[0]} {apex} NS +norecurse",
                         f"dig +short {apex} DS", f"dig @8.8.8.8 {apex} SOA +dnssec  # then add +cd to compare"],
        },
        "propagation": {
            "rows": [{"k": f"{r.name} ({r.ip})", "v": f"A: {', '.join(r.a) or r.status}\nNS: {', '.join(r.ns) or '–'}"} for r in obs.resolvers]
                    + ([{"k": "Authoritative", "v": "A: " + (", ".join(obs.authoritative_a) or "none")}] if obs.authoritative_a is not None else []),
            "commands": [f"dig +short @{r.ip} {h} A" for r in obs.resolvers] + [f"dig +short @{r.ip} {apex} NS" for r in obs.resolvers[:1]],
        },
    }
    t = obs.tls
    raw["tls"] = {
        "rows": _rows([
            ("Result", ("valid" if t.verified else f"invalid: {t.verify_message}") if t and not t.error else (t.error if t else "not checked")),
            ("Covers", ", ".join(t.cert.sans) if t and t.cert else None),
            ("Issuer", t.cert.issuer if t and t.cert else None),
            ("Valid from", f"{t.cert.not_before:%d %b %Y}" if t and t.cert else None),
            ("Valid until", f"{t.cert.not_after:%d %b %Y}" if t and t.cert else None),
            ("Protocol", t.version if t else None),
            ("Certificates sent", str(t.chain_length) if t and t.chain_length else None),
        ]),
        "commands": [f"echo | openssl s_client -connect {h}:443 -servername {h} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName"],
    }
    def hops(r):
        return "\n".join(f"{x.status}  {x.url}" for x in r.hops) if r and r.hops else (r.error if r else None)
    r = obs.https
    raw["http"] = {
        "rows": _rows([
            ("https:// chain", hops(obs.https)),
            ("http:// chain", hops(obs.http)),
            (f"{obs.other_host}", hops(obs.other) if obs.other_host else None),
            ("Certificate errors", "ignored to read the response" if r and r.cert_error_ignored else None),
            ("IPv4 connect", _conn(obs.ipv4)),
            ("IPv6 connect", _conn(obs.ipv6)),
            ("CDN or proxy", obs.cdn or "none detected"),
        ]) + [{"k": k, "v": v} for k, v in sorted((r.headers if r else {}).items())
              if k in {"server", "via", "x-powered-by", "cache-control", "strict-transport-security",
                       "content-security-policy", "x-frame-options", "location", "content-type", "age", "x-cache"}
              or k in {"cf-ray", "x-amz-cf-id", "x-served-by", "x-vercel-id", "x-nf-request-id", "x-azure-ref"}],
        "commands": [f"curl -sIL {obs.url}", f"curl -sI http://{h}/", f"curl -6 -sI --max-time 5 https://{h}/"],
    }
    reg = obs.registration
    raw["registration"] = {
        "rows": _rows([
            ("Domain", reg.domain or apex),
            ("Registrar", reg.registrar),
            ("Registered", f"{reg.created:%d %b %Y}" if reg.created else None),
            ("Expires", f"{reg.expires:%d %b %Y}" if reg.expires else None),
            ("Status", ", ".join(reg.statuses)),
            ("Note", reg.error),
        ]),
        "commands": [f"whois {reg.domain or apex}", f"curl -s https://rdap.org/domain/{reg.domain or apex}"],
    }
    return raw


def _conn(c) -> str | None:
    if not c:
        return None
    if c.ok:
        return f"{c.address}: connected in {c.ms} ms"
    return f"{c.address}: {c.error}"


def _facts(obs: Observation) -> dict[str, str]:
    """Stable, comparable values. The page diffs these between checks to show what changed."""
    t = obs.tls
    return {
        "Registry nameservers": ", ".join(obs.delegation.parent_ns) or "unknown",
        "IPv4 addresses": ", ".join(obs.dns.a) or obs.dns.status,
        "IPv6 addresses": ", ".join(obs.dns.aaaa) or "none",
        "Certificate valid until": f"{t.cert.not_after:%Y-%m-%d}" if t and t.cert else "no certificate",
        "Certificate verified": "yes" if t and t.verified else "no",
        "HTTPS status": str(obs.https.status) if obs.https and obs.https.status else (obs.https.error if obs.https else "–") or "–",
        "CDN or proxy": obs.cdn or "none",
        "DNSSEC": {True: "broken", False: "valid", None: "off"}[obs.delegation.dnssec_broken] if obs.delegation.ds_present else "off",
    }
