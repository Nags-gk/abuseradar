"""CI regression gate: fail the build if detection quality drops below these floors."""
import json
import sys
from pathlib import Path

r = json.loads((Path(__file__).resolve().parent.parent / "results" / "eval.json").read_text())
s, m = r["summary"], r["model"]
checks = {
    "every held-out campaign detected": s["test_campaigns_detected_fused"] == s["test_campaigns"],
    "every taken-over account flagged": s["compromised_flagged_test"] == s["compromised_accounts_test"],
    "page precision >= 0.97": s["page_precision_test"] >= 0.97,
    "false pages <= 0.2 per 1k accounts/day": s["false_pages_per_1k_accounts_day"] <= 0.2,
    "LightGBM PR-AUC >= 0.95": m["lightgbm"]["pr_auc"] >= 0.95,
    "evasive stuffing (C12) login recall >= 0.6": m["per_campaign_recall"].get("C12", 0) >= 0.6,
}
for name, ok in checks.items():
    print(("PASS " if ok else "FAIL ") + name)
sys.exit(0 if all(checks.values()) else 1)
