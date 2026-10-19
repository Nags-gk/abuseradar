"""End-to-end scoring of the detection stack against the labeled campaigns.

Metrics are reported for the held-out test window (days 10-20) unless noted:
* campaign recall and time to detect, per layer (rules / ML / graph / fused);
* compromised-account coverage: how many taken-over accounts are flagged, and how
  many minutes after the attacker's first successful login;
* alert precision (an alert is a true positive when its evidence contains at least
  one attacker event) and false incidents per 1,000 accounts per day.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .ml import SPLIT_DAY


def _first_hit(alerts: pd.DataFrame, ids: set) -> pd.Timestamp | None:
    hit = alerts[alerts.evidence.apply(lambda ev: any(e in ids for e in ev))]
    return None if hit.empty else pd.to_datetime(hit.window_end, utc=True).min()


def evaluate(con, alerts: pd.DataFrame, incidents: pd.DataFrame, campaigns: pd.DataFrame,
             start: pd.Timestamp, n_accounts: int) -> dict:
    cut = start + pd.Timedelta(days=SPLIT_DAY)
    lab = con.execute("SELECT event_id, ts, label, attack, account_id, event_type, success FROM events WHERE label <> ''").df()
    lab["ts"] = pd.to_datetime(lab.ts, utc=True)
    alerts = alerts.copy()
    alerts["window_start"] = pd.to_datetime(alerts.window_start, utc=True)
    alerts["window_end"] = pd.to_datetime(alerts.window_end, utc=True)
    test_alerts = alerts[alerts.window_start >= cut]

    # campaigns
    per_campaign = []
    for c in campaigns.itertuples():
        ids = set(lab.loc[lab.label == c.label, "event_id"])
        t0 = lab.loc[lab.label == c.label, "ts"].min()
        row = dict(label=c.label, attack=c.attack, variant=c.variant, window="test" if t0 >= cut else "train",
                   events=len(ids), compromised=int(c.compromised))
        for layer in ("rule", "ml", "graph", None):
            sub = alerts if layer is None else alerts[alerts.layer == layer]
            first = _first_hit(sub, ids)
            name = layer or "fused"
            row[f"{name}_detected"] = first is not None
            row[f"{name}_minutes_to_detect"] = None if first is None else round((first - t0).total_seconds() / 60, 1)
        rules_hit = sorted({r for r, ev in zip(alerts.rule_id, alerts.evidence, strict=False) if any(e in ids for e in ev)})
        row["rules"] = rules_hit
        per_campaign.append(row)
    pc = pd.DataFrame(per_campaign)

    # compromised accounts: first successful attacker login per account
    comp = lab[(lab.event_type == "login") & lab.success].groupby("account_id").agg(t0=("ts", "min"), label=("label", "first"))
    acct_rows = []
    for acct, r in comp.iterrows():
        ids = set(lab.loc[lab.account_id == acct, "event_id"])
        first = _first_hit(alerts, ids)
        acct_rows.append(dict(account=acct, label=r.label, test=r.t0 >= cut, flagged=first is not None,
                              minutes=None if first is None else max(0.0, (first - r.t0).total_seconds() / 60)))
    ca = pd.DataFrame(acct_rows)
    cat = ca[ca.test]

    # precision and false-incident rate (test window)
    labelled = set(lab.event_id)
    tp_mask = test_alerts.evidence.apply(lambda ev: any(e in labelled for e in ev))
    inc = incidents.copy()
    inc["first_seen"] = pd.to_datetime(inc.first_seen, utc=True)
    inc_t = inc[inc.first_seen >= cut]
    inc_tp = inc_t.evidence.apply(lambda ev: any(e in labelled for e in ev))
    test_days = (con.execute("SELECT epoch(max(ts)) FROM events").fetchone()[0] - cut.timestamp()) / 86400
    by_rule = (test_alerts.assign(tp=tp_mask).groupby("rule_id")
               .agg(alerts=("tp", "size"), true_positive=("tp", "sum")).reset_index())
    by_rule["precision"] = (by_rule.true_positive / by_rule.alerts).round(4)

    test_c = pc[pc.window == "test"]
    return dict(
        campaigns=pc.replace({np.nan: None}).to_dict("records"),
        summary=dict(
            test_campaigns=int(len(test_c)),
            test_campaigns_detected_fused=int(test_c.fused_detected.sum()),
            test_campaigns_detected_rules_only=int(test_c.rule_detected.sum()),
            median_minutes_to_detect=float(np.nanmedian(test_c.fused_minutes_to_detect.astype(float))),
            compromised_accounts_test=int(len(cat)),
            compromised_flagged_test=int(cat.flagged.sum()),
            median_minutes_compromise_to_alert=float(np.nanmedian(cat.minutes.astype(float))) if cat.flagged.any() else None,
            alerts_test=int(len(test_alerts)), alert_precision_test=round(float(tp_mask.mean()), 4) if len(test_alerts) else None,
            incidents_test=int(len(inc_t)), incident_precision_test=round(float(inc_tp.mean()), 4) if len(inc_t) else None,
            false_incidents_per_1k_accounts_day=round(float((~inc_tp).sum()) / n_accounts * 1000 / test_days, 3),
            alert_to_incident_ratio=round(len(test_alerts) / max(len(inc_t), 1), 1),
            pages_test=int(inc_t.severity.isin(["high", "critical"]).sum()),
            page_precision_test=round(float(inc_tp[inc_t.severity.isin(["high", "critical"])].mean()), 4),
            false_pages_per_1k_accounts_day=round(float((~inc_tp & inc_t.severity.isin(["high", "critical"])).sum())
                                                  / n_accounts * 1000 / test_days, 3),
        ),
        by_rule=by_rule.to_dict("records"),
    )
