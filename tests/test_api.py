"""API tests with the network layer replaced by a fixture observation."""

from fastapi.testclient import TestClient

from tests.test_rules import healthy
from triage import app as app_module
from triage.model import Delegation


def client(monkeypatch, obs):
    monkeypatch.setattr(app_module, "collect", lambda url, expected=None: obs)
    app_module._hits.clear()
    return TestClient(app_module.app)


def test_diagnose_healthy(monkeypatch):
    body = client(monkeypatch, healthy()).get("/api/diagnose", params={"url": "www.example.com"}).json()
    assert body["verdict"]["tone"] == "ok"
    assert body["diagnoses"] == []
    assert [s["step"] for s in body["path"]] == ["Name lookup", "Nameservers", "CDN or proxy", "Certificate", "Web server"]
    assert body["healthy"] and body["reply"]
    assert set(body["raw"]) == {"dns", "delegation", "propagation", "tls", "http", "registration"}


def test_diagnose_problem_leads_verdict(monkeypatch):
    obs = healthy(delegation=Delegation(parent_ns=["ns1.hostco.net"], child_ns=["ns9.other.example"], ds_present=False))
    body = client(monkeypatch, obs).get("/api/diagnose", params={"url": "www.example.com"}).json()
    assert body["verdict"]["tone"] == "warn"
    assert body["diagnoses"][0]["id"] == "DEL-02"
    assert body["path"][1]["tone"] == "warn"


def test_bad_input_is_400(monkeypatch):
    monkeypatch.setattr(app_module, "collect", lambda url, expected=None: (_ for _ in ()).throw(ValueError("Enter a domain name rather than an IP address.")))
    app_module._hits.clear()
    r = TestClient(app_module.app).get("/api/diagnose", params={"url": "1.2.3.4"})
    assert r.status_code == 400 and "IP address" in r.json()["detail"]


def test_rate_limit(monkeypatch):
    c = client(monkeypatch, healthy())
    codes = [c.get("/api/diagnose", params={"url": "example.com"}).status_code for _ in range(app_module.RATE_LIMIT + 1)]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}


def test_rate_limit_ignores_spoofed_forwarded_for(monkeypatch):
    c = client(monkeypatch, healthy())
    codes = [c.get("/api/diagnose", params={"url": "example.com"},
                   headers={"x-forwarded-for": f"10.0.0.{i}, 198.51.100.7"}).status_code
             for i in range(app_module.RATE_LIMIT + 1)]
    assert codes[-1] == 429  # changing the spoofable first entry doesn't reset the limit
