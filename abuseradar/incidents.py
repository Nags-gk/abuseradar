"""Alert fusion. Alerts on the same entity within 6 hours of each other become one
incident, so on-call gets one page per attacker footprint instead of one per rule
firing per window."""
from __future__ import annotations

import pandas as pd

from .rules import SEVERITY_RANK

GAP = pd.Timedelta(hours=6)


def build_incidents(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return pd.DataFrame()
    a = alerts.sort_values(["entity_type", "entity", "window_start"]).reset_index(drop=True)
    a["window_start"] = pd.to_datetime(a.window_start, utc=True)
    a["window_end"] = pd.to_datetime(a.window_end, utc=True)
    inc_ids, cur, last_key, last_end = [], -1, None, None
    for r in a.itertuples():
        key = (r.entity_type, r.entity)
        if key != last_key or r.window_start - last_end > GAP:
            cur += 1
            last_end = r.window_end
        last_end = max(last_end, r.window_end)
        last_key = key
        inc_ids.append(cur)
    a["incident"] = inc_ids
    rows = []
    for i, g in a.groupby("incident"):
        ev = sorted({e for lst in g.evidence for e in lst})
        sev = max(g.severity, key=lambda s: SEVERITY_RANK[s])
        rows.append(dict(incident_id=f"INC-{i + 1:05d}", entity_type=g.entity_type.iloc[0], entity=g.entity.iloc[0],
                         first_seen=g.window_start.min(), last_seen=g.window_end.max(), severity=sev,
                         attacks=sorted(set(g.attack)), rules=sorted(set(g.rule_id)), layers=sorted(set(g.layer)),
                         mitre=sorted(set(g.mitre)), alerts=len(g), evidence=ev,
                         summary="; ".join(dict.fromkeys(f"{r}: {d}" for r, d in zip(g.rule_id, g.detail, strict=False)).keys())[:600]))
    return pd.DataFrame(rows)
