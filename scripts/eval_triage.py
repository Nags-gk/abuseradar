"""Score Gemini triage on real pipeline incidents (needs GEMINI_API_KEY).

Sample: true-positive incidents (evidence contains attacker events) and false-positive
incidents (no attacker events; mostly travellers flagged by impossible travel).
A triage is correct when it calls a true positive `true_positive` and a false
positive `benign` (or `needs_review`, counted separately). Also reports how often the
grounding guard rejected the model's answer.
"""
import json
import os
import sys
import time
from pathlib import Path

import pandas as pd

from abuseradar import store, triage

ROOT = Path(__file__).resolve().parent.parent
n_each = int(sys.argv[1]) if len(sys.argv) > 1 else 10
con = store.connect()
store.load_parquet(con, ROOT / "data")
inc = pd.read_parquet(ROOT / "data" / "incidents.parquet")
lab = set(con.execute("SELECT event_id FROM events WHERE label <> ''").df().event_id)
inc["tp"] = inc.evidence.apply(lambda e: any(x in lab for x in e))
sample = pd.concat([inc[inc.tp].sample(n_each, random_state=1), inc[~inc.tp].sample(min(n_each, int((~inc.tp).sum())), random_state=1)])
index = triage.PlaybookIndex(triage.load_playbook())
rows = []
for r in sample.itertuples():
    i = r._asdict()
    i["evidence"], i["attacks"], i["rules"] = [int(x) for x in r.evidence], list(r.attacks), list(r.rules)
    out = triage.triage(con, i, index, os.environ["GEMINI_API_KEY"])
    v = out["result"]["verdict"]
    rows.append(dict(incident=r.incident_id, truth="true_positive" if r.tp else "false_positive", rules=list(r.rules), mode=out["mode"],
                     verdict=v, guard=out["guard"], tools=[t[0] for t in out["tool_calls"]], latency_s=out["latency_s"],
                     correct=(v == "true_positive") if r.tp else (v == "benign")))
    print(rows[-1]["incident"], rows[-1]["truth"], rows[-1]["mode"], v, flush=True)
    time.sleep(6)
df = pd.DataFrame(rows)
llm = df[df["mode"] == "llm"]
res = dict(model=triage.MODEL, incidents=len(df), llm_answers=len(llm), guard_rejections=int((df["mode"] == "fallback").sum()),
           accuracy_llm_answers=round(float(llm.correct.mean()), 4) if len(llm) else None,
           tp_called_tp=int(((llm.truth == "true_positive") & (llm.verdict == "true_positive")).sum()), tp_total=int((llm.truth == "true_positive").sum()),
           fp_called_benign=int(((llm.truth == "false_positive") & (llm.verdict == "benign")).sum()),
           fp_called_needs_review=int(((llm.truth == "false_positive") & (llm.verdict == "needs_review")).sum()),
           fp_total=int((llm.truth == "false_positive").sum()), median_latency_s=float(df.latency_s.median()), rows=rows)
(ROOT / "results" / "triage_eval.json").write_text(json.dumps(res, indent=2))
print(json.dumps({k: v for k, v in res.items() if k != "rows"}, indent=2))
