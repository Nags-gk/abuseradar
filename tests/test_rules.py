import pytest

from abuseradar.rules import OUTPUT_COLUMNS, load_rules, run_rule

from .conftest import ev

RULES = {r.id: r for r in load_rules()}


def fire(con, rid):
    return run_rule(con, RULES[rid])


def test_every_rule_has_metadata_and_attack_mapping():
    assert len(RULES) >= 9
    for r in RULES.values():
        assert r.mitre.startswith("T1"), r.id
        assert r.response and r.description


@pytest.mark.parametrize("rid", sorted(RULES))
def test_rule_output_schema_on_benign_traffic(mk, rid):
    con = mk([ev(i * 30) for i in range(10)])
    out = fire(con, rid)
    assert list(out.columns[1:7]) == OUTPUT_COLUMNS
    assert out.empty, f"{rid} fired on plain benign logins"


def test_r001_ip_stuffing_threshold(mk):
    hits = [ev(i, account_id=f"x{i}", ip="9.9.9.9", success=False, status=401) for i in range(5)]
    assert len(fire(mk(hits), "R001")) == 1
    assert fire(mk(hits[:3]), "R001").empty  # 3 accounts is below the floor


def test_r003_spray_needs_same_hash_across_accounts(mk):
    spray = [ev(i, account_id=f"x{i}", ip=f"9.9.9.{i % 5}", success=False, pw_hash="abc123") for i in range(25)]
    assert len(fire(mk(spray), "R003")) == 1
    distinct = [ev(i, account_id=f"x{i}", success=False, pw_hash=f"h{i}") for i in range(25)]
    assert fire(mk(distinct), "R003").empty


def test_r004_suppresses_vpn_user_with_known_device(mk):
    vpn = [ev(0), ev(60, lat=52.0, lon=5.0)]  # same device, 8,800 km in an hour
    assert fire(mk(vpn), "R004").empty
    takeover = [ev(0), ev(60, lat=52.0, lon=5.0, device_fp="fp-new")]
    assert len(fire(mk(takeover), "R004")) == 1


def test_r005_takeover_chain(mk):
    history = [ev(-1000 + i) for i in range(3)]
    chain = [ev(0, asn=65000, ip="7.7.7.7", device_fp="fp-evil"), ev(10, event_type="mfa_change"),
             ev(15, event_type="email_change")]
    out = fire(mk(history + chain), "R005")
    assert len(out) == 1 and "mfa_change" in out.detail[0]
    known_network = [ev(0, device_fp="fp-new"), ev(10, event_type="mfa_change")]
    assert fire(mk(history + known_network), "R005").empty


def test_r006_device_clone(mk):
    rows = [ev(i * 60, event_type="device_checkin", device_id="d1") for i in range(3)]
    rows += [ev(30, event_type="device_checkin", device_id="d1", asn=65001, ip="5.5.5.5")]
    assert len(fire(mk(rows), "R006")) == 1


def test_r007_enumeration(mk):
    rows = [ev(i * 0.05, event_type="api_call", device_id=f"d{i:06d}", status=404) for i in range(60)]
    assert len(fire(mk(rows), "R007")) == 1


def test_r008_signup_burst(mk):
    rows = [ev(i, event_type="signup", account_id=f"n{i}", device_fp="fp-ring") for i in range(6)]
    assert len(fire(mk(rows), "R008")) == 1
