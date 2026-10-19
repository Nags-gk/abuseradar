"""Run the whole stack: simulate -> load -> rules + ML + graph -> incidents -> evaluate.

    python -m abuseradar.pipeline            # writes data/, results/eval.json, web/data/*.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd

from . import evaluate, features, graph, incidents, ml, rules, sim, store

ROOT = Path(__file__).resolve().parent.parent


def _jsonable(df: pd.DataFrame) -> list[dict]:
    out = df.copy()
    for c in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[c]):
            out[c] = out[c].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return json.loads(out.to_json(orient="records"))


def run(cfg: sim.Config | None = None, out_dir: Path = ROOT) -> dict:
    cfg = cfg or sim.Config()
    timings = {}
    t = time.time()
    events, campaigns, asns = sim.generate(cfg)
    world, _ = sim.build_world(cfg)
    timings["simulate_s"] = round(time.time() - t, 1)
    data = out_dir / "data"; data.mkdir(exist_ok=True)
    events.to_parquet(data / "events.parquet"); campaigns.to_parquet(data / "campaigns.parquet")
    asns.to_parquet(data / "asns.parquet"); world.accounts[["account_id", "country"]].to_parquet(data / "accounts.parquet")

    con = store.connect()
    store.load_parquet(con, data)
    start = pd.Timestamp(cfg.start, tz="UTC")

    t = time.time(); rule_alerts = rules.run_all(con); timings["rules_s"] = round(time.time() - t, 2)
    t = time.time(); feats = features.login_features(con); res = ml.train(feats, start); ml_al = ml.ml_alerts(res)
    timings["ml_s"] = round(time.time() - t, 1)
    t = time.time(); g_al, gstats = graph.ring_alerts(con); timings["graph_s"] = round(time.time() - t, 2)

    alerts = pd.concat([rule_alerts, ml_al, g_al], ignore_index=True)
    inc = incidents.build_incidents(alerts)
    report = evaluate.evaluate(con, alerts, inc, campaigns, start, cfg.accounts)
    report["model"] = res.metrics
    report["graph"] = gstats
    report["dataset"] = dict(events=int(len(events)), accounts=cfg.accounts, days=cfg.days,
                             attack_events=int((events.label != "").sum()), campaigns=int(len(campaigns)),
                             event_types=events.event_type.value_counts().to_dict())
    report["timings"] = timings
    report["rules"] = [dict(id=r.id, name=r.name, mitre=r.mitre, severity=r.severity, entity=r.entity,
                            description=r.description, response=r.response, false_positives=r.false_positives)
                       for r in rules.load_rules()]

    res_dir = out_dir / "results"; res_dir.mkdir(exist_ok=True)
    res.model.booster_.save_model(str(res_dir / "model.txt"))
    (res_dir / "model_meta.json").write_text(json.dumps(dict(threshold=res.threshold, features=features.FEATURES)))
    (res_dir / "eval.json").write_text(json.dumps(report, indent=2, default=str))
    web = out_dir / "web" / "data"; web.mkdir(parents=True, exist_ok=True)
    inc_out = inc.sort_values("first_seen").copy()
    inc_out["evidence_count"] = inc_out.evidence.apply(len)
    inc_out["evidence"] = inc_out.evidence.apply(lambda e: e[:40])
    (web / "incidents.json").write_text(json.dumps(_jsonable(inc_out)))
    (web / "eval.json").write_text(json.dumps(report, default=str))
    hourly = con.execute("""SELECT time_bucket(INTERVAL 1 HOUR, ts) AS hour,
        count(*) FILTER (WHERE event_type = 'login' AND NOT success) AS failed_logins,
        count(*) FILTER (WHERE event_type = 'login' AND success) AS ok_logins,
        count(*) FILTER (WHERE label <> '') AS attack_events FROM events GROUP BY 1 ORDER BY 1""").df()
    (web / "hourly.json").write_text(json.dumps(_jsonable(hourly)))
    inc.to_parquet(data / "incidents.parquet")
    alerts.to_parquet(data / "alerts.parquet")
    return report


if __name__ == "__main__":
    r = run()
    print(json.dumps(r["summary"], indent=2))
    print(json.dumps(r["model"]["lightgbm"], indent=2))
    for c in r["campaigns"]:
        print(c["label"], c["attack"], c["variant"], c["window"], "rule", c["rule_detected"], "ml", c["ml_detected"],
              "graph", c["graph_detected"], "ttd", c["fused_minutes_to_detect"], c["rules"])
