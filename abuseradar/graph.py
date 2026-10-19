"""Graph detection for fake-account rings.

Accounts, device fingerprints and IPs become nodes; a signup links an account to the
fingerprint and IP it used. Organic signups produce tiny components. A ring that
reuses a handful of phones and proxies collapses into one large component, even when
it spreads its signups over days to stay under per-day rules.
"""
from __future__ import annotations

import networkx as nx
import pandas as pd

MIN_ACCOUNTS = 8


def ring_alerts(con, min_accounts: int = MIN_ACCOUNTS) -> tuple[pd.DataFrame, dict]:
    su = con.execute("""SELECT event_id, ts, account_id, device_fp, ip FROM events WHERE event_type = 'signup'""").df()
    follow = con.execute("""SELECT event_id, account_id FROM events WHERE event_type = 'referral_claim'""").df()
    g = nx.Graph()
    for r in su.itertuples():
        g.add_edge(("acct", r.account_id), ("fp", r.device_fp))
        g.add_edge(("acct", r.account_id), ("ip", r.ip))
    rows, sizes = [], []
    for i, comp in enumerate(nx.connected_components(g)):
        accts = {n[1] for n in comp if n[0] == "acct"}
        sizes.append(len(accts))
        if len(accts) < min_accounts:
            continue
        ev = su[su.account_id.isin(accts)]
        ev2 = follow[follow.account_id.isin(accts)]
        fps = sum(1 for n in comp if n[0] == "fp"); ips = sum(1 for n in comp if n[0] == "ip")
        # alert time = when the component first reached the threshold, as a streaming
        # graph job re-run on each signup would have seen it
        crossed = ev.sort_values("ts").ts.iloc[min_accounts - 1]
        rows.append(dict(rule_id="G1", entity=f"ring-{i}", window_start=ev.ts.min(), window_end=crossed,
                         evidence=ev.event_id.tolist() + ev2.event_id.tolist(), metric=float(len(accts)),
                         detail=f"{len(accts)} accounts share {fps} device fingerprints and {ips} IPs",
                         attack="fake_account_ring", severity="high", mitre="T1585 Establish Accounts",
                         layer="graph", entity_type="ring"))
    s = pd.Series(sizes)
    stats = dict(components=int(len(s)), largest=int(s.max()) if len(s) else 0,
                 singleton_share=round(float((s == 1).mean()), 4) if len(s) else 0.0, rings=len(rows))
    return pd.DataFrame(rows), stats
