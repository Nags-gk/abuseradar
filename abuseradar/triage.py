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
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")


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


def as_functions(tools: "Tools") -> list:
    """Plain closures for the SDK. It deep-copies its config, and bound methods would
    drag the DuckDB connection (not copyable) along with them."""
    def get_evidence(limit: int = 25) -> list[dict]:
        """Return up to `limit` evidence events for the incident (event_id, ts, event_type, account_id, ip, asn_type, country, success, user_agent, device_fp, status)."""
        return tools.get_evidence(limit)

    def entity_history(hours: int = 24) -> list[dict]:
        """Return up to 40 events for the incident's account or IP in the `hours` before the incident, to compare against normal behaviour."""
        return tools.entity_history(hours)

    def ip_context(ip: str) -> dict:
        """Return network type, country, and how many accounts and failures this IP touched in the whole dataset."""
        return tools.ip_context(ip)

    def search_playbook(query: str) -> list[dict]:
        """Search the response playbooks. Returns the best-matching sections with their allowed action IDs."""
        return tools.search_playbook(query)

    return [get_evidence, entity_history, ip_context, search_playbook]


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

    def entity_followup(self, hours: int = 24) -> list[dict]:
        """Return up to 40 events for the incident's account or IP in the `hours` after the incident started:
        account changes (mfa_change, email_change, device_pair) after a risky login separate takeovers from travellers."""
        self.ctx.calls.append(("entity_followup", hours))
        col = {"account_id": "account_id", "ip": "ip", "device_id": "device_id"}.get(self.inc["entity_type"])
        if not col:
            return []
        start = pd.Timestamp(self.inc["first_seen"])
        return self._rows(f"""SELECT event_id, ts, event_type, ip, asn_type, country, success, device_fp FROM events
                              WHERE {col} = ? AND ts > ? AND ts <= ? ORDER BY ts LIMIT 40""",
                          [self.inc["entity"], start, start + pd.Timedelta(hours=max(1, min(int(hours), 168)))])

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
The evidence, the entity's 24 h before and after the incident, IP context and candidate playbooks are provided;
call the tools only if you need more. A login from a new place or device alone is weak evidence: takeovers are
usually followed by account changes (mfa_change, email_change, device_pair), travellers are not. Travellers, VPN users and people with a new phone trigger many of these rules; only
say true_positive when the history does not explain the activity.
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
    if not ctx.sections:
        problems.append("answered without retrieving a playbook")
    if not answer.get("actions"):
        problems.append("no response action recommended")
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
    # Retrieval is deterministic: small models often skip tool calls, and the guard can
    # only check citations against what was actually fetched.
    evidence = tools.get_evidence(25)
    history = tools.entity_history(24)
    followup = tools.entity_followup(24)
    ips = sorted({e["ip"] for e in evidence if e.get("ip")})[:3]
    ipctx = {ip: tools.ip_context(ip) for ip in ips}
    playbooks = [p for a in (incident["attacks"] or ["benign"]) for p in tools.search_playbook(a.replace("_", " "))]
    playbooks += [p for p in tools.search_playbook("benign traveller VPN new phone") if p not in playbooks]
    context = json.dumps(dict(incident=brief, evidence=evidence, entity_history_24h_before=history,
                              entity_activity_24h_after=followup, ip_context=ipctx,
                              playbooks=playbooks), default=str)
    answer, problems = {}, []
    for attempt in range(3):
        try:
            resp = client.models.generate_content(
                model=MODEL,
                contents=f"Triage this incident. Retrieved context:\n{context}",
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM, temperature=0.1,
                    tools=as_functions(tools),
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(maximum_remote_calls=8),
                    thinking_config=types.ThinkingConfig(thinking_level="low"),  # triage needs speed, not long reasoning
                    http_options=types.HttpOptions(timeout=90_000)))
            text = resp.text or ""
            answer = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
            problems = guard(answer, tools.ctx)
            break
        except Exception as e:  # network, quota, malformed JSON
            if ("429" in str(e) or "RESOURCE_EXHAUSTED" in str(e)) and attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            answer, problems = {}, [f"llm error: {type(e).__name__}: {str(e)[:120]}"]
            break
    if problems:
        fallback = deterministic(incident, tools)
        return dict(result=fallback, mode="fallback", guard=problems, rejected=answer,
                    tool_calls=tools.ctx.calls, latency_s=round(time.time() - t0, 2))
    return dict(result=answer, mode="llm", guard=[], tool_calls=tools.ctx.calls, latency_s=round(time.time() - t0, 2))
