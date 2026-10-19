"""HTTP API for the live demo (Cloud Run).

The service is public, so it applies the controls its own threat model calls for
(docs/threat-model.md): per-client and global rate limits, strict input validation,
a request-size cap, an allow-listed CORS origin, security headers, generic error
messages, and structured JSON logs that record every rate-limit and validation
rejection as a signal.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Literal

import lightgbm as lgb
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from . import features, store, triage

ROOT = Path(os.environ.get("ABUSERADAR_ROOT", Path(__file__).resolve().parent.parent))
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://nags-gk.github.io,http://localhost:8000").split(",")
MAX_BODY = 64 * 1024

log = logging.getLogger("abuseradar")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


def jlog(**kw):
    log.info(json.dumps({"severity": "INFO", **kw}, default=str))


class RateLimiter:
    """Token bucket per key. Instance-local, which is acceptable for a single
    Cloud Run instance (max-instances=1); a shared store would be needed beyond that."""

    def __init__(self, rate_per_min: float, burst: int):
        self.rate, self.burst = rate_per_min / 60.0, burst
        self.state: dict[str, tuple[float, float]] = defaultdict(lambda: (burst, time.monotonic()))
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self.lock:
            tokens, last = self.state[key]
            now = time.monotonic()
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.state[key] = (tokens - 1 if ok else tokens, now)
            return ok


class State:
    def __init__(self):
        self.con = store.connect()
        store.load_parquet(self.con, ROOT / "data")
        self.incidents = pd.read_parquet(ROOT / "data" / "incidents.parquet")
        self.incidents["first_seen"] = pd.to_datetime(self.incidents.first_seen, utc=True)
        self.by_id = {r.incident_id: r._asdict() for r in self.incidents.itertuples(index=False)}
        self.eval = json.loads((ROOT / "results" / "eval.json").read_text())
        meta = json.loads((ROOT / "results" / "model_meta.json").read_text())
        self.threshold, self.feature_names = meta["threshold"], meta["features"]
        self.booster = lgb.Booster(model_file=str(ROOT / "results" / "model.txt"))
        self.context = self.con.execute("""SELECT * FROM events WHERE event_type = 'login'
            AND ts >= (SELECT max(ts) FROM events) - INTERVAL 24 HOUR""").df()
        self.accounts = self.con.execute("SELECT account_id FROM accounts").df()
        self.index = triage.PlaybookIndex(triage.load_playbook())
        self.triage_cache: dict[str, dict] = {}
        self.triage_today = [time.strftime("%Y-%m-%d"), 0]
        self.db_lock = threading.Lock()


S: State | None = None
general = RateLimiter(rate_per_min=60, burst=30)
triage_limit = RateLimiter(rate_per_min=3, burst=3)
TRIAGE_DAILY_CAP = int(os.environ.get("TRIAGE_DAILY_CAP", "200"))

app = FastAPI(title="AbuseRadar", version="1.0", docs_url="/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"], max_age=600)


def state() -> State:
    global S
    if S is None:
        S = State()
    return S


def client_ip(req: Request) -> str:
    # Cloud Run's front end appends the caller's address; take the right-most entry,
    # which the client cannot spoof by sending its own X-Forwarded-For.
    xff = req.headers.get("x-forwarded-for", "")
    return xff.split(",")[-1].strip() if xff else (req.client.host if req.client else "unknown")


@app.middleware("http")
async def guardrails(req: Request, call_next):
    rid = uuid.uuid4().hex[:12]
    ip = client_ip(req)
    if int(req.headers.get("content-length") or 0) > MAX_BODY:
        jlog(event="rejected", reason="body_too_large", ip=ip, path=req.url.path, rid=rid)
        return JSONResponse({"error": "request too large"}, status_code=413)
    if not general.allow(ip):
        jlog(event="rate_limited", ip=ip, path=req.url.path, rid=rid)
        return JSONResponse({"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "30"})
    t0 = time.time()
    try:
        resp = await call_next(req)
    except Exception as e:  # never leak stack traces to clients
        jlog(event="error", ip=ip, path=req.url.path, rid=rid, error=type(e).__name__)
        resp = JSONResponse({"error": "internal error", "request_id": rid}, status_code=500)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                         "Strict-Transport-Security": "max-age=31536000", "X-Request-Id": rid,
                         "Cache-Control": "no-store"})
    jlog(event="request", ip=ip, method=req.method, path=req.url.path, status=resp.status_code,
         ms=round((time.time() - t0) * 1000, 1), rid=rid)
    return resp


def _clean(v):
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    if isinstance(v, np.ndarray):
        return [_clean(x) for x in v.tolist()]
    if isinstance(v, (pd.Timestamp, datetime)):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    return v


def _incident_out(r: dict, full=False) -> dict:
    out = {k: _clean(v) for k, v in r.items() if k != "evidence"}
    out["evidence_count"] = len(r["evidence"])
    if full:
        out["evidence"] = [int(e) for e in r["evidence"][:200]]
    return out


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/v1/summary")
def summary():
    e = state().eval
    return {"summary": e["summary"], "model": {k: e["model"][k] for k in ("threshold", "lightgbm", "isolation_forest", "per_campaign_recall")},
            "dataset": e["dataset"], "graph": e["graph"]}


@app.get("/v1/incidents")
def incidents(severity: Literal["low", "medium", "high", "critical"] | None = None,
              attack: str | None = Query(None, pattern=r"^[a-z_]{3,32}$"),
              limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    df = state().incidents
    if severity:
        df = df[df.severity == severity]
    if attack:
        df = df[df.attacks.apply(lambda a: attack in list(a))]
    rows = df.sort_values("first_seen").iloc[offset: offset + limit]
    return {"total": int(len(df)), "items": [_incident_out(r._asdict()) for r in rows.itertuples(index=False)]}


ID_RE = re.compile(r"^INC-\d{5}$")


@app.get("/v1/incidents/{incident_id}")
def incident(incident_id: str):
    if not ID_RE.match(incident_id) or incident_id not in state().by_id:
        raise HTTPException(404, "not found")
    return _incident_out(state().by_id[incident_id], full=True)


@app.post("/v1/incidents/{incident_id}/triage")
def run_triage(incident_id: str, request: Request):
    st = state()
    if not ID_RE.match(incident_id) or incident_id not in st.by_id:
        raise HTTPException(404, "not found")
    if incident_id in st.triage_cache:
        return {**st.triage_cache[incident_id], "cached": True}
    ip = client_ip(request)
    if not triage_limit.allow(ip):
        jlog(event="rate_limited", ip=ip, path="triage")
        raise HTTPException(429, "triage rate limit: 3 per minute")
    today = time.strftime("%Y-%m-%d")
    if st.triage_today[0] != today:
        st.triage_today[:] = [today, 0]
    if st.triage_today[1] >= TRIAGE_DAILY_CAP:
        raise HTTPException(429, "daily triage budget used up; try tomorrow")
    st.triage_today[1] += 1
    inc = dict(st.by_id[incident_id])
    inc["evidence"] = [int(e) for e in inc["evidence"]]
    inc["attacks"], inc["rules"] = list(inc["attacks"]), list(inc["rules"])
    with st.db_lock:
        out = triage.triage(st.con, inc, st.index)
    out = json.loads(json.dumps(out, default=_clean))
    st.triage_cache[incident_id] = out
    jlog(event="triage", incident=incident_id, mode=out["mode"], guard=out["guard"], latency_s=out["latency_s"])
    return {**out, "cached": False}


class LoginEvent(BaseModel):
    ts: datetime
    account_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    ip: str
    asn: int = Field(ge=0, le=4294967295)
    asn_type: Literal["residential", "mobile", "hosting"]
    country: str = Field(pattern=r"^[A-Z]{2}$")
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
    device_fp: str = Field(default="", max_length=64)
    user_agent: str = Field(default="", max_length=256)
    success: bool
    pw_hash: str = Field(default="", pattern=r"^[0-9a-f]{0,16}$")

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        ipaddress.ip_address(v)
        return v


class ScoreRequest(BaseModel):
    events: list[LoginEvent] = Field(min_length=1, max_length=200)


@app.post("/v1/score")
def score(req: ScoreRequest):
    """Score login events against the last 24 h of traffic with the trained model.
    Features are computed by the same SQL used in training, so online and offline
    scores match."""
    st = state()
    new = pd.DataFrame([e.model_dump() for e in req.events])
    new["ts"] = pd.to_datetime(new.ts, utc=True)
    base = int(st.context.event_id.max()) + 1
    new.insert(0, "event_id", np.arange(base, base + len(new)))
    new["event_type"], new["label"], new["attack"] = "login", "", ""
    for c in ("device_id", "endpoint"):
        new[c] = ""
    new["status"] = np.where(new.success, 200, 401)
    # Per-account features (networks and devices seen before, prior logins) need the
    # account's full history, not just the last 24 h; without it every login looks new.
    with st.db_lock:
        hist = st.con.execute("""SELECT * FROM events WHERE event_type = 'login'
            AND account_id IN (SELECT unnest(?))""", [sorted(set(new.account_id))]).df()
    ctx = pd.concat([st.context, hist], ignore_index=True).drop_duplicates("event_id")
    frame = pd.concat([ctx, new[st.context.columns]], ignore_index=True)
    con = store.connect()
    store.load_frames(con, frame, st.accounts)
    f = features.login_features(con)
    f = f.set_index("event_id").loc[new.event_id].reset_index()  # keep request order
    p = st.booster.predict(f[st.feature_names])
    contrib = st.booster.predict(f[st.feature_names], pred_contrib=True)[:, :-1]
    out = []
    for i, (_, row) in enumerate(f.iterrows()):
        top = np.argsort(-contrib[i])[:3]
        out.append(dict(account_id=row.account_id, ip=row.ip, score=round(float(p[i]), 4),
                        alert=bool(p[i] >= st.threshold),
                        top_factors=[{"feature": st.feature_names[j], "value": _clean(row[st.feature_names[j]]),
                                      "contribution": round(float(contrib[i][j]), 3)} for j in top]))
    return {"threshold": st.threshold, "results": out}


@app.exception_handler(Exception)
async def unhandled(_, exc):
    return JSONResponse({"error": "internal error"}, status_code=500)
