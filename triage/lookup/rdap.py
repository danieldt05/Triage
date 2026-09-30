"""Domain registration via RDAP, the JSON successor to WHOIS.

IANA publishes which RDAP server handles each TLD; we fetch that list once
and cache it. Some ccTLDs don't run RDAP; those return an error, not a guess.
"""

from __future__ import annotations

import threading
from datetime import datetime

import requests

from triage.model import Registration

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 6
_bootstrap: dict[str, str] | None = None
_lock = threading.Lock()


def _servers() -> dict[str, str]:
    global _bootstrap
    with _lock:
        if _bootstrap is None:
            data = requests.get(BOOTSTRAP_URL, timeout=TIMEOUT).json()
            table = {}
            for tlds, urls in data.get("services", []):
                for tld in tlds:
                    table[tld.lower()] = urls[0].rstrip("/") + "/"
            _bootstrap = table
    return _bootstrap


def lookup(apex: str) -> Registration:
    reg = Registration()
    tld = apex.rsplit(".", 1)[-1].lower()
    try:
        base = _servers().get(tld)
    except (requests.RequestException, ValueError):
        reg.error = "Couldn't load the RDAP server list from IANA."
        return reg
    if not base:
        reg.error = f"The .{tld} registry doesn't offer RDAP."
        return reg

    # The zone we found may be a delegated subzone (shop.example.com); walk up
    # until the registry recognises the name, stopping at the registered level.
    labels = apex.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            resp = requests.get(base + "domain/" + name, timeout=TIMEOUT,
                                headers={"Accept": "application/rdap+json"})
        except requests.RequestException:
            reg.error = "The registry's RDAP server didn't respond."
            return reg
        if resp.status_code == 404:
            continue
        if resp.status_code != 200:
            reg.error = f"The registry's RDAP server returned HTTP {resp.status_code}."
            return reg
        return _parse(name, resp.json())
    reg.not_found = True
    reg.domain = apex
    return reg


def _parse(name: str, data: dict) -> Registration:
    reg = Registration(domain=name)
    reg.statuses = [s for s in data.get("status", []) if isinstance(s, str)]
    for event in data.get("events", []):
        when = _date(event.get("eventDate"))
        action = event.get("eventAction")
        if action == "registration":
            reg.created = when
        elif action == "expiration":
            reg.expires = when
        elif action == "last changed":
            reg.updated = when
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            reg.registrar = _vcard_name(entity) or entity.get("handle")
    return reg


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _vcard_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3])
    return None
