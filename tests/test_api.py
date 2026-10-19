"""API tests run against the pipeline outputs (python -m abuseradar.pipeline first)."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not (ROOT / "data" / "incidents.parquet").exists(), reason="run the pipeline first")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from abuseradar import api
    api.general.state.clear()
    return TestClient(api.app)


LOGIN = dict(ts="2026-09-21T23:00:00Z", account_id="a00010", ip="10.20.30.40", asn=64512, asn_type="residential",
             country="US", lat=37.0, lon=-120.0, device_fp="fpabc", user_agent="HomeApp/5.2 iOS", success=True, pw_hash="")


def test_health_and_security_headers(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "max-age" in r.headers["strict-transport-security"]


def test_incidents_list_and_detail(client):
    r = client.get("/v1/incidents", params={"severity": "critical", "limit": 5}).json()
    assert r["total"] > 0 and all(i["severity"] == "critical" for i in r["items"])
    one = client.get(f"/v1/incidents/{r['items'][0]['incident_id']}").json()
    assert one["evidence"]


@pytest.mark.parametrize("bad", ["INC-1", "../etc/passwd", "INC-00001' OR 1=1--", "INC-99999"])
def test_bad_incident_ids_are_404(client, bad):
    assert client.get(f"/v1/incidents/{bad}").status_code == 404


def test_score_flags_stuffing_and_passes_normal_login(client):
    stuffing = [dict(LOGIN, account_id=f"u{i}", ip="203.0.113.9", asn=64600, asn_type="hosting", success=False,
                     device_fp=f"fpx{i}", user_agent="python-requests/2.32", ts=f"2026-09-21T23:{i:02d}:00Z", pw_hash=f"{i:012x}")
                for i in range(12)]
    from abuseradar import api
    home = api.state().con.execute("""SELECT ip, asn, asn_type, country, lat, lon, device_fp, user_agent FROM events
        WHERE account_id = 'a00010' AND event_type = 'login' AND success ORDER BY ts DESC LIMIT 1""").df().iloc[0]
    normal = dict(LOGIN, **{k: (v.item() if hasattr(v, "item") else v) for k, v in home.items()})
    r = client.post("/v1/score", json={"events": stuffing + [normal]}).json()
    scores = [x["score"] for x in r["results"]]
    assert max(scores[:12]) > r["threshold"]
    assert r["results"][-1]["alert"] is False
    assert len(r["results"][0]["top_factors"]) == 3


@pytest.mark.parametrize("patch", [{"ip": "not-an-ip"}, {"country": "usa"}, {"account_id": "a; DROP TABLE"},
                                   {"lat": 200}, {"asn_type": "satellite"}])
def test_score_rejects_malformed_input(client, patch):
    assert client.post("/v1/score", json={"events": [dict(LOGIN, **patch)]}).status_code == 422


def test_score_caps_batch_size(client):
    assert client.post("/v1/score", json={"events": [LOGIN] * 201}).status_code == 422


def test_triage_without_key_uses_deterministic_path(client, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    iid = client.get("/v1/incidents", params={"severity": "critical", "limit": 1}).json()["items"][0]["incident_id"]
    r = client.post(f"/v1/incidents/{iid}/triage").json()
    assert r["mode"] == "deterministic" and r["result"]["actions"]


def test_cors_only_allows_the_dashboard_origin(client):
    ok = client.options("/v1/summary", headers={"Origin": "https://nags-gk.github.io", "Access-Control-Request-Method": "GET"})
    bad = client.options("/v1/summary", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://nags-gk.github.io"
    assert "access-control-allow-origin" not in bad.headers


def test_rate_limit_returns_429(client):
    from abuseradar import api
    api.general.state.clear()
    codes = [client.get("/health").status_code for _ in range(40)]
    assert 429 in codes
    api.general.state.clear()
