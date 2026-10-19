"""Login risk models.

* LightGBM, supervised, trained only on the first 10 days. The decision threshold is
  chosen from out-of-fold predictions on those days, never from the test window.
* IsolationForest, unsupervised, as a no-labels baseline.

Every alert carries the three features that pushed its score up most (LightGBM
per-feature contributions), so an analyst sees why it fired.
"""
from __future__ import annotations

from dataclasses import dataclass

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import StratifiedKFold

from .features import FEATURES

SPLIT_DAY = 10
PARAMS = dict(n_estimators=300, learning_rate=0.05, num_leaves=31, min_child_samples=20,
              subsample=0.8, subsample_freq=1, colsample_bytree=0.8, verbose=-1, random_state=7)


@dataclass
class ModelResult:
    model: lgb.LGBMClassifier
    threshold: float
    train: pd.DataFrame
    test: pd.DataFrame
    metrics: dict


def split(df: pd.DataFrame, start: pd.Timestamp):
    cut = start + pd.Timedelta(days=SPLIT_DAY)
    return df[df.ts < cut].copy(), df[df.ts >= cut].copy()


def pick_threshold(y, p, min_precision=0.99) -> float:
    prec, rec, thr = precision_recall_curve(y, p)
    ok = np.where(prec[:-1] >= min_precision)[0]
    return float(thr[ok[0]]) if len(ok) else 0.5


def _pr_at(y, p, thr):
    pred = p >= thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    return dict(precision=round(tp / max(tp + fp, 1), 4), recall=round(tp / max(tp + fn, 1), 4), tp=tp, fp=fp, fn=fn)


def train(features: pd.DataFrame, start: pd.Timestamp) -> ModelResult:
    tr, te = split(features, start)
    X, y = tr[FEATURES], tr["y"].values
    oof = np.zeros(len(tr))
    for a, b in StratifiedKFold(5, shuffle=True, random_state=7).split(X, y):
        m = lgb.LGBMClassifier(**PARAMS).fit(X.iloc[a], y[a])
        oof[b] = m.predict_proba(X.iloc[b])[:, 1]
    thr = pick_threshold(y, oof)
    model = lgb.LGBMClassifier(**PARAMS).fit(X, y)
    te["score"] = model.predict_proba(te[FEATURES])[:, 1]
    tr["score"] = oof
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=7).fit(X)
    iso_te = -iso.score_samples(te[FEATURES])
    metrics = dict(
        train_logins=int(len(tr)), test_logins=int(len(te)), test_attack_logins=int(te.y.sum()),
        threshold=float(f"{thr:.3g}"),
        lightgbm=dict(pr_auc=round(average_precision_score(te.y, te.score), 4), **_pr_at(te.y.values, te.score.values, thr)),
        isolation_forest=dict(pr_auc=round(average_precision_score(te.y, iso_te), 4)),
        per_attack_recall={a: round(float((g.score >= thr).mean()), 4) for a, g in te[te.y == 1].groupby("attack")},
        per_campaign_recall={c: round(float((g.score >= thr).mean()), 4) for c, g in te[te.y == 1].groupby("label")},
        feature_importance=dict(sorted(zip(FEATURES, (model.booster_.feature_importance("gain") /
                                                      model.booster_.feature_importance("gain").sum()).round(4).tolist(), strict=False),
                                       key=lambda kv: -kv[1])[:8]),
    )
    return ModelResult(model, thr, tr, te, metrics)


def explain(model: lgb.LGBMClassifier, rows: pd.DataFrame, k: int = 3) -> list[str]:
    contrib = model.predict(rows[FEATURES], pred_contrib=True)[:, :-1]
    out = []
    for i, c in enumerate(contrib):
        top = np.argsort(-c)[:k]
        out.append(", ".join(f"{FEATURES[j]}={rows.iloc[i][FEATURES[j]]:.4g}" for j in top))
    return out


def ml_alerts(res: ModelResult) -> pd.DataFrame:
    """Group test-window logins above threshold into alerts: per account for successful
    logins (possible takeover), per IP for failures (attack infrastructure), per hour."""
    hits = res.test[res.test.score >= res.threshold].copy()
    if hits.empty:
        return pd.DataFrame()
    hits["reason"] = explain(res.model, hits)
    hits["entity"] = np.where(hits.success == 1, hits.account_id, hits.ip)
    hits["entity_type"] = np.where(hits.success == 1, "account_id", "ip")
    hits["window_start"] = hits.ts.dt.floor("1h")
    rows = []
    for (ent, et, ws), g in hits.groupby(["entity", "entity_type", "window_start"]):
        rows.append(dict(rule_id="ML1", entity=ent, window_start=ws, window_end=ws + pd.Timedelta(hours=1),
                         evidence=g.event_id.tolist(), metric=float(g.score.max()),
                         detail=f"{len(g)} risky logins, max score {g.score.max():.2f}; top factors: {g.reason.iloc[g.score.argmax()]}",
                         attack="account_takeover" if et == "account_id" else "credential_stuffing",
                         severity="high" if g.score.max() > 0.9 else "medium",
                         mitre="T1110 Brute Force / T1078 Valid Accounts", layer="ml", entity_type=et))
    return pd.DataFrame(rows)
