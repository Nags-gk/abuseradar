"""LLM incident triage with retrieval and a grounding guard.

The assistant gets an incident and four read-only tools (evidence rows, entity
history, IP context, playbook search). Gemini decides which tools to call, then
returns a structured verdict. The guard rejects any answer that

* cites an event ID that was never returned by a tool,
* recommends an action ID that is not in a playbook section it retrieved, or
* names an attack type that does not exist,

and falls back to a deterministic triage built from the rule metadata. Without a
GEMINI_API_KEY the deterministic path is used directly, so the service always works.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

PLAYBOOK = Path(__file__).resolve().parent.parent / "docs" / "playbooks.md"
ATTACKS = {"credential_stuffing", "password_spray", "account_takeover", "device_clone",
           "api_enumeration", "fake_account_ring", "benign"}
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")


@dataclass
class Section:
    name: str
    text: str
    actions: dict


def load_playbook(path: Path = PLAYBOOK) -> list[Section]:
    parts = re.split(r"^## ", path.read_text(), flags=re.M)[1:]
    out = []
    for p in parts:
        name, body = p.split("\n", 1)
        acts = dict(re.findall(r"\[(A\d+)\]\s*(.+)", body))
        out.append(Section(name.strip(), body.strip(), acts))
    return out


class PlaybookIndex:
    """TF-IDF retrieval over playbook sections (small corpus, no embedding service needed)."""

    def __init__(self, sections: list[Section]):
        self.sections = sections
        self.vec = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.m = self.vec.fit_transform([f"{s.name} {s.text}" for s in sections])

    def search(self, query: str, k: int = 2) -> list[Section]:
        sims = cosine_similarity(self.vec.transform([query]), self.m)[0]
        return [self.sections[i] for i in sims.argsort()[::-1][:k]]


@dataclass
class Context:
    """Records everything the tools returned, which is what the guard checks against."""
    seen_events: set = field(default_factory=set)
    sections: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)


class Tools:
    def __init__(self, con, incident: dict, index: PlaybookIndex):
        self.con, self.inc, self.index, self.ctx = con, incident, index, Context()

    def _rows(self, sql, params) -> list[dict]:
        df = self.con.execute(sql, params).df()
        if "event_id" in df:
            self.ctx.seen_events.update(int(x) for x in df.event_id)
        for c in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[c]):
                df[c] = df[c].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return df.to_dict("records")

    def get_evidence(self, limit: int = 25) -> list[dict]:
        """Return up to `limit` evidence events for the incident (event_id, ts, event_type, account_id, ip, asn_type, country, success, user_agent, device_fp, status)."""
        self.ctx.calls.append(("get_evidence", limit))
        ids = [int(e) for e in self.inc["evidence"][: max(1, min(int(limit), 50))]]
        return self._rows("""SELECT event_id, ts, event_type, account_id, ip, asn_type, country, success,
                                    user_agent, device_fp, status FROM events WHERE event_id IN (SELECT unnest(?)) ORDER BY ts""", [ids])

    def entity_history(self, hours: int = 24) -> list[dict]:
        """Return up to 40 events for the incident's account or IP in the `hours` before the incident, to compare against normal behaviour."""
        self.ctx.calls.append(("entity_history", hours))
        col = {"account_id": "account_id", "ip": "ip", "device_id": "device_id"}.get(self.inc["entity_type"])
        if not col:
            return []
        start = pd.Timestamp(self.inc["first_seen"])
        return self._rows(f"""SELECT event_id, ts, event_type, ip, asn_type, country, success, device_fp FROM events
                              WHERE {col} = ? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 40""",
                          [self.inc["entity"], start - pd.Timedelta(hours=max(1, min(int(hours), 168))), start])

    def ip_context(self, ip: str) -> dict:
        """Return network type, country, and how many accounts and failures this IP touched in the whole dataset."""
        self.ctx.calls.append(("ip_context", ip))
        r = self.con.execute("""SELECT any_value(asn_type) asn_type, any_value(country) country, count(DISTINCT account_id) accounts,
                                count(*) FILTER (WHERE event_type='login' AND NOT success) failed_logins,
                                count(*) FILTER (WHERE event_type='login' AND success) ok_logins
                                FROM events WHERE ip = ?""", [ip]).df().to_dict("records")
        return r[0] if r else {}

    def search_playbook(self, query: str) -> list[dict]:
        """Search the response playbooks. Returns the best-matching sections with their allowed action IDs."""
        self.ctx.calls.append(("search_playbook", query))
        hits = self.index.search(query)
        for s in hits:
            self.ctx.sections[s.name] = s
        return [{"section": s.name, "text": s.text, "actions": s.actions} for s in hits]


SYSTEM = """You are a detection-and-response analyst triaging an abuse incident on a smart-home device cloud.
Use the tools to look at the evidence, the entity's history and the playbook before answering.
Rules: cite only event IDs returned by tools; recommend only action IDs from playbook sections you retrieved;
if the evidence looks like normal behaviour (travel, VPN, new phone) say benign. Reply with JSON only:
{"verdict": "true_positive|benign|needs_review", "confidence": 0-1, "attack": "<one of credential_stuffing,
password_spray, account_takeover, device_clone, api_enumeration, fake_account_ring, benign>",
"summary": "<= 3 sentences", "affected_accounts": <int>, "actions": ["A1", ...], "cited_event_ids": [..],
"playbook_sections": ["..."]}"""


def guard(answer: dict, ctx: Context) -> list[str]:
    problems = []
    if answer.get("verdict") not in {"true_positive", "benign", "needs_review"}:
        problems.append("bad verdict")
    if answer.get("attack") not in ATTACKS:
        problems.append(f"unknown attack {answer.get('attack')!r}")
    cited = {int(e) for e in answer.get("cited_event_ids", []) if str(e).lstrip("-").isdigit()}
    if not cited:
        problems.append("no evidence cited")
    if cited - ctx.seen_events:
        problems.append(f"cites events never returned by a tool: {sorted(cited - ctx.seen_events)[:5]}")
    allowed = {a for s in ctx.sections.values() for a in s.actions}
    bad = set(answer.get("actions", [])) - allowed
    if bad:
        problems.append(f"actions not in retrieved playbooks: {sorted(bad)}")
    return problems


def deterministic(incident: dict, tools: Tools) -> dict:
    ev = tools.get_evidence(10)
    attack = incident["attacks"][0] if incident["attacks"] else "benign"
    sec = tools.search_playbook(attack)[0]
    accounts = len({e["account_id"] for e in ev})
    return dict(verdict="true_positive" if incident["severity"] in ("high", "critical") else "needs_review",
                confidence=0.6, attack=attack,
                summary=f"{', '.join(incident['rules'])} fired on {incident['entity_type']} {incident['entity']}: {incident['summary'][:200]}",
                affected_accounts=accounts, actions=list(sec["actions"])[:3],
                cited_event_ids=[e["event_id"] for e in ev[:5]], playbook_sections=[sec["section"]])


def triage(con, incident: dict, index: PlaybookIndex | None = None, api_key: str | None = None) -> dict:
    index = index or PlaybookIndex(load_playbook())
    tools = Tools(con, incident, index)
    key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
    t0 = time.time()
    if not key:
        out = deterministic(incident, tools)
        return dict(result=out, mode="deterministic", guard=[], tool_calls=tools.ctx.calls, latency_s=round(time.time() - t0, 2))
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=key)
    brief = {k: incident[k] for k in ("incident_id", "entity_type", "entity", "severity", "attacks", "rules", "summary", "alerts")}
    brief["evidence_count"] = len(incident["evidence"])
    try:
        resp = client.models.generate_content(
            model=MODEL,
            contents=f"Triage this incident:\n{json.dumps(brief, default=str)}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM, temperature=0.1,
                tools=[tools.get_evidence, tools.entity_history, tools.ip_context, tools.search_playbook],
                automatic_function_calling=types.AutomaticFunctionCallingConfig(maximum_remote_calls=8)))
        text = resp.text or ""
        answer = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        problems = guard(answer, tools.ctx)
    except Exception as e:  # network, quota, malformed JSON
        answer, problems = {}, [f"llm error: {type(e).__name__}: {str(e)[:120]}"]
    if problems:
        fallback = deterministic(incident, tools)
        return dict(result=fallback, mode="fallback", guard=problems, rejected=answer,
                    tool_calls=tools.ctx.calls, latency_s=round(time.time() - t0, 2))
    return dict(result=answer, mode="llm", guard=[], tool_calls=tools.ctx.calls, latency_s=round(time.time() - t0, 2))
