"""The diagnosis engine.

A rule is a pure function: Observation in, Diagnosis (or None) out. No
network, no globals, no randomness, so every rule is unit-testable with a
hand-built Observation (see tests/test_rules.py).

Rules report the level of a problem and how confident they are. Confidence
comes from how many independent signals agree, not from a gut feeling, and a
rule stays silent when its input is missing: "we couldn't tell" must never
become a confident wrong diagnosis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from triage.model import Observation

LEVEL_ORDER = {"error": 0, "warning": 1, "info": 2}


@dataclass
class Diagnosis:
    id: str
    level: str                 # error | warning | info
    step: str                  # dns | nameservers | edge | tls | server | registration
    title: str
    summary: str
    evidence: list[tuple[str, str]] = field(default_factory=list)  # (where it came from, what we saw)
    fix: list[str] = field(default_factory=list)
    reply: str = ""            # plain-English message for the customer
    confidence: str = "High"   # High | Medium | Low
    confidence_reason: str = ""


Rule = Callable[[Observation], "Diagnosis | list[Diagnosis] | None"]
RULES: list[tuple[str, Rule]] = []


def rule(rule_id: str):
    def register(fn: Rule) -> Rule:
        RULES.append((rule_id, fn))
        fn.rule_id = rule_id  # type: ignore[attr-defined]
        return fn
    return register


def run(obs: Observation) -> list[Diagnosis]:
    # Import here so each module's @rule decorators register exactly once.
    from triage.rules import delegation, dns_rules, registration, tls_rules, web_rules  # noqa: F401

    found: list[Diagnosis] = []
    for _, fn in RULES:
        result = fn(obs)
        if result is None:
            continue
        found.extend(result if isinstance(result, list) else [result])
    return sorted(found, key=lambda d: LEVEL_ORDER[d.level])
