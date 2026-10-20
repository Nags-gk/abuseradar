import pandas as pd

from abuseradar import features, graph, incidents, triage
from abuseradar.sim import Config, generate

from .conftest import ev, make_con


def test_simulator_is_deterministic_and_labelled():
    a, ca, _ = generate(Config(accounts=300, days=21, seed=3))
    b, cb, _ = generate(Config(accounts=300, days=21, seed=3))
    pd.testing.assert_frame_equal(a, b)
    assert set(ca.label) == set(a.loc[a.label != "", "label"])
    assert (a.loc[a.attack == "", "label"] == "").all()


def test_features_are_causal():
    """Adding events after a login must not change that login's features."""
    past = [ev(i, account_id=f"x{i}", ip="9.9.9.9", success=False) for i in range(4)]
    future = [ev(30 + i, account_id=f"y{i}", ip="9.9.9.9", success=False) for i in range(10)]
    f1 = features.login_features(make_con(past)).set_index("ts")[features.FEATURES]
    f2 = features.login_features(make_con(past + future)).set_index("ts")[features.FEATURES]
    pd.testing.assert_frame_equal(f1, f2.loc[f1.index])


def test_incidents_merge_within_gap_and_split_beyond():
    t = pd.Timestamp("2026-09-10T00:00Z")
    def al(h, rule="R001", ent="1.2.3.4", sev="high"):
        return dict(rule_id=rule, entity=ent, entity_type="ip", window_start=t + pd.Timedelta(hours=h),
                    window_end=t + pd.Timedelta(hours=h + 1), evidence=[h], metric=1.0, detail="d",
                    attack="credential_stuffing", severity=sev, mitre="T1110", layer="rule")
    inc = incidents.build_incidents(pd.DataFrame([al(0), al(2, "R002", sev="critical"), al(20)]))
    assert len(inc) == 2
    assert inc.iloc[0].severity == "critical" and inc.iloc[0].alerts == 2


def test_graph_finds_ring_not_organic_signups():
    rows = [ev(i, event_type="signup", account_id=f"r{i}", device_fp=f"fp{i % 3}", ip=f"8.8.8.{i % 2}") for i in range(12)]
    rows += [ev(i, event_type="signup", account_id=f"o{i}", device_fp=f"own{i}", ip=f"6.6.{i}.1") for i in range(30)]
    alerts, stats = graph.ring_alerts(make_con(rows))
    assert len(alerts) == 1 and alerts.metric[0] == 12
    assert stats["largest"] == 12


def test_guard_rejects_hallucinated_events_and_actions():
    ctx = triage.Context(seen_events={1, 2}, sections={"credential_stuffing": triage.Section("credential_stuffing", "", {"A1": "x"})})
    ok = dict(verdict="true_positive", attack="credential_stuffing", cited_event_ids=[1], actions=["A1"])
    assert triage.guard(ok, ctx) == []
    assert triage.guard({**ok, "cited_event_ids": [99]}, ctx)
    assert triage.guard({**ok, "actions": ["A7"]}, ctx)
    assert triage.guard({**ok, "attack": "made_up"}, ctx)


def test_playbook_retrieval_finds_the_right_section():
    idx = triage.PlaybookIndex(triage.load_playbook())
    assert idx.search("one password tried on many accounts spraying")[0].name == "password_spray"
    assert idx.search("device serial checking in from two networks")[0].name == "device_clone"


def test_deterministic_triage_passes_its_own_guard():
    con = make_con([ev(i, account_id=f"x{i}", ip="9.9.9.9", success=False) for i in range(5)])
    inc = dict(incident_id="INC-00001", entity_type="ip", entity="9.9.9.9", severity="high",
               attacks=["credential_stuffing"], rules=["R001"], summary="5 accounts", alerts=1,
               evidence=[0, 1, 2, 3, 4], first_seen="2026-09-10T12:00:00Z")
    out = triage.triage(con, inc, api_key="")
    tools = triage.Tools(con, inc, triage.PlaybookIndex(triage.load_playbook()))
    tools.get_evidence(10); tools.search_playbook("credential_stuffing")
    assert out["mode"] == "deterministic"
    assert triage.guard(out["result"], tools.ctx) == []


def test_guard_rejects_answers_that_skip_the_playbook_or_actions():
    ctx = triage.Context(seen_events={1})
    ans = dict(verdict="true_positive", attack="account_takeover", cited_event_ids=[1], actions=[])
    problems = triage.guard(ans, ctx)
    assert any("playbook" in p for p in problems) and any("action" in p for p in problems)
