"""Detection-as-code: each rule is a YAML file holding metadata, an ATT&CK mapping and
one SQL query. Every query returns the same columns, so rules can be added without
touching the engine:

    entity, window_start, window_end, evidence (list of event_ids), metric, detail
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
REQUIRED = {"id", "name", "attack", "mitre", "severity", "entity", "description", "response", "sql"}
OUTPUT_COLUMNS = ["entity", "window_start", "window_end", "evidence", "metric", "detail"]
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    attack: str
    mitre: str
    severity: str
    entity: str
    description: str
    response: str
    sql: str
    false_positives: str = ""


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for f in sorted(directory.glob("*.yml")):
        spec = yaml.safe_load(f.read_text())
        missing = REQUIRED - spec.keys()
        if missing:
            raise ValueError(f"{f.name}: missing {sorted(missing)}")
        if spec["severity"] not in SEVERITY_RANK:
            raise ValueError(f"{f.name}: bad severity {spec['severity']}")
        rules.append(Rule(**{k: spec[k] for k in Rule.__dataclass_fields__ if k in spec}))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


def run_rule(con, rule: Rule) -> pd.DataFrame:
    df = con.execute(rule.sql).df()
    if list(df.columns) != OUTPUT_COLUMNS:
        raise ValueError(f"{rule.id} returned {list(df.columns)}, expected {OUTPUT_COLUMNS}")
    df.insert(0, "rule_id", rule.id)
    df["attack"], df["severity"], df["mitre"], df["layer"] = rule.attack, rule.severity, rule.mitre, "rule"
    df["entity_type"] = rule.entity
    return df


def run_all(con, rules: list[Rule] | None = None) -> pd.DataFrame:
    rules = rules or load_rules()
    out = [run_rule(con, r) for r in rules]
    return pd.concat([o for o in out if len(o)], ignore_index=True) if out else pd.DataFrame()
