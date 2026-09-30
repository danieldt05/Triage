# Triage

**Paste a customer's link. Find out why their website isn't working, in plain English, in seconds.**

![tests](https://github.com/YOUR-USERNAME/triage/actions/workflows/tests.yml/badge.svg)
· **[Live demo](https://YOUR-APP.onrender.com)**

![Triage diagnosing a site](docs/screenshot.png)

When a customer says "my website is down", a support engineer usually runs a
string of commands (`dig`, `curl`, `openssl`, `whois`), reads the raw output,
and works out which of a dozen usual causes it is. Triage does those lookups in
parallel and runs the results through a set of diagnostic rules. It tells you:

- **what's wrong**, as one sentence at the top of the page
- **where it breaks**, on a five-step path: name lookup → nameservers → CDN → certificate → web server
- **how to fix it**, step by step
- **what to tell the customer**, as a ready-to-send reply
- **how to check it yourself**, with the exact commands for the domain you entered

It works with any DNS provider, CDN or host.

---

## Why I built this

*[Write this in your own words: two or three sentences about seeing the same
handful of causes behind "my site is down" tickets during your support work,
and wanting a tool that explains the cause rather than dumping raw output.]*

## What it checks

| Area | What Triage looks at |
|---|---|
| DNS | A/AAAA/CNAME, MX, TXT, DMARC, CAA, SOA; dangling CNAMEs |
| Delegation | Nameservers at the registry vs. the zone's own NS records; nameservers that don't answer |
| DNSSEC | Stale or mismatched DS records that make validating resolvers refuse to answer |
| Propagation | Answers from Google, Cloudflare, Quad9 and OpenDNS public resolvers |
| Certificate | Expiry (relative to its lifetime), wrong hostname, self-signed, untrusted or incomplete chain |
| Web server | Redirect chain and loops, error pages, HTTP→HTTPS redirect, IPv4 vs IPv6 reachability |
| Registration | Registrar, expiry and hold statuses via RDAP |
| www vs apex | Whether both versions of the address work |

## How a diagnosis is made

Every diagnosis comes from a **named rule**: a small, pure Python function that
takes the collected observations and returns a diagnosis or nothing. No
network, no randomness, so every rule is unit-tested with hand-built inputs.

```python
@rule("DEL-01")
def not_delegated_to_expected(obs):
    if not obs.expected or not obs.delegation.parent_ns:
        return None
    if matches_expected(obs.expected, obs.delegation.parent_ns) is not False:
        return None   # matches, or we can't tell: stay silent
    ...
```

Each diagnosis carries its **evidence** (what was observed and where), a
**confidence** level with the reason for it, a **fix**, and a **customer reply**.

| Rule | Detects |
|---|---|
| `DNS-01` | The name doesn't exist in DNS |
| `DNS-02` | No address records, or a CNAME pointing at a name that no longer exists |
| `DNS-03` | DNS lookups fail (SERVFAIL / timeout) |
| `DNS-05` | Broken DNSSEC (validation fails, succeeds with checking disabled) |
| `DNS-07` | Resolvers disagree: propagation in progress (or CDN routing, flagged as low confidence) |
| `DEL-01` | Domain delegated to a different DNS provider than the customer expects |
| `DEL-02` | Registry and zone list different nameservers |
| `DEL-03` | Delegated nameservers that don't answer for the domain |
| `TLS-01` | Expired / not-yet-valid / soon-expiring certificate |
| `TLS-02` | Wrong hostname, self-signed, untrusted or incomplete chain |
| `HTTP-01` | Server errors, including "CDN is up but the origin behind it isn't" |
| `HTTP-02` | 4xx responses (403/429 treated as probable bot protection, low confidence) |
| `HTTP-03` | Redirect loops |
| `HTTP-04` | No HTTP→HTTPS redirect, or HTTPS not working at all |
| `NET-01` | IPv6 address doesn't respond while IPv4 works |
| `NET-02` | Server doesn't respond at all |
| `HOST-01` | `www` and the bare domain behave differently |
| `REG-01` | Domain unregistered, expired, expiring or on hold |

## Designed not to be confidently wrong

A diagnostic tool that is confidently wrong once stops being trusted. Some of
the decisions that came out of testing against real domains:

- **"We couldn't tell" never becomes an error.** If every nameserver seems
  broken but the domain still resolves, that contradiction means direct
  queries are blocked from where Triage runs. It reports "not verified", not
  "your nameservers are broken".
- **Low-confidence findings don't headline.** A 403 is often bot protection,
  so the verdict says "check manually" instead of "broken".
- **One root cause, one finding.** An expired certificate isn't also reported
  as a separate verification failure.
- **Known alternative explanations are named.** Resolvers returning different
  addresses is normal for CDNs, so it's a low-confidence note, not a warning.
- **IPv6 is only judged if the server running Triage has IPv6.** Otherwise
  the result is marked inconclusive.

## Security

Triage fetches URLs that users type in, so it's built defensively:

- **SSRF protection.** Refuses to connect to private, loopback or link-local
  addresses, re-checked on every redirect hop, so it can't be used to probe
  the network it runs on.
- **Read-only.** Only DNS queries, a TLS handshake and ordinary page
  requests (headers only). No port scanning, no path probing, no brute force.
- **Rate limited** per client, using the proxy-appended address so it can't be
  bypassed with a spoofed `X-Forwarded-For` header, plus a server-wide cap on
  concurrent checks.
- **No HTML injection.** Headers and records from arbitrary servers are
  rendered as text, never as HTML.

## Architecture

```
triage/
├── lookup/          network I/O only: returns plain data, never judges
│   ├── dnsq.py        records, delegation, propagation, DNSSEC (dnspython)
│   ├── tls.py         certificate via two handshakes (verified + raw)
│   ├── web.py         redirect chain, headers, IPv4/IPv6 connectivity
│   ├── rdap.py        registration via IANA's RDAP bootstrap
│   ├── providers.py   DNS provider / CDN recognition from public signals
│   └── collect.py     runs all lookups in parallel → Observation
├── rules/           pure functions: Observation → Diagnosis
├── report.py        verdict, request path, healthy checks, raw data
├── app.py           FastAPI: /api/diagnose + the web page
└── static/          the web page (vanilla JS, no build step)
```

The split between `lookup/` (facts) and `rules/` (judgement) is the core
design choice: rules are testable without a network, and every conclusion can
be traced back to an observed fact.

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn triage.app:app --reload
# open http://localhost:8000
pytest -q
```

API docs are served at `/api/docs`.

## Deploy (free)

1. Push this repo to GitHub.
2. On [Render](https://render.com): **New → Blueprint**, pick the repo. `render.yaml` does the rest.
3. Replace the demo and badge links at the top of this file.

## Known limitations

- **Single vantage point.** Results reflect what the server running Triage
  sees; a problem limited to one ISP or region may not show up.
- **DNS rebinding.** The SSRF check resolves a name before connecting, and the
  HTTP client resolves it again. A determined attacker could race that. Fully
  closing it means pinning connections to the checked IP.
- **RDAP coverage.** Some country-code registries don't offer RDAP, so their
  registration data is shown as unavailable rather than guessed.
- **In-memory rate limit.** Per process; resets on restart. Fine for one small
  instance, not for a scaled deployment.
- **Free hosting cold starts.** The first request after a quiet period can be slow.

## Roadmap

- Pin HTTP connections to the resolved IP to close the rebinding gap
- Email deliverability checks (SPF/DMARC evaluation, MX reachability)
- Shareable permalinks for saved results

## License

MIT
