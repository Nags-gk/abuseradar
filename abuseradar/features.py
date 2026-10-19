"""Per-login features computed in SQL with causal windows: each feature uses only events
at or before the login it describes, so nothing the model sees comes from the future."""
from __future__ import annotations

import pandas as pd

FEATURES = [
    "success", "unknown_user", "ip_attempts_1h", "ip_fail_1h", "ip_fail_ratio_1h",
    "asn_attempts_1h", "asn_fail_1h", "acct_fail_1h", "pw_accounts_6h",
    "asn_seen_before", "fp_seen_before", "prior_logins", "asn_hosting", "asn_mobile",
    "scripted_ua", "km_from_prev", "kmh_from_prev", "hour_utc",
]

SQL = """
WITH l AS (
  SELECT *, CASE WHEN success THEN 0 ELSE 1 END AS fail
  FROM events WHERE event_type = 'login'),
f AS (
  SELECT event_id, ts, account_id, ip, asn, label, attack,
    CASE WHEN success THEN 1 ELSE 0 END AS success,
    CASE WHEN account_id IN (SELECT account_id FROM accounts) THEN 0 ELSE 1 END AS unknown_user,
    count(*) OVER ip1h AS ip_attempts_1h,
    sum(fail) OVER ip1h AS ip_fail_1h,
    count(*) OVER asn1h AS asn_attempts_1h,
    sum(fail) OVER asn1h AS asn_fail_1h,
    sum(fail) OVER acct1h AS acct_fail_1h,
    CASE WHEN pw_hash = '' THEN 0 ELSE count(*) OVER pw6h END AS pw_accounts_6h,  -- empty hash = not logged, not shared
    count(*) OVER (PARTITION BY account_id, asn ORDER BY ts ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS asn_seen_before,
    count(*) OVER (PARTITION BY account_id, device_fp ORDER BY ts ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS fp_seen_before,
    count(*) OVER (PARTITION BY account_id ORDER BY ts ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS prior_logins,
    CASE WHEN asn_type = 'hosting' THEN 1 ELSE 0 END AS asn_hosting,
    CASE WHEN asn_type = 'mobile' THEN 1 ELSE 0 END AS asn_mobile,
    CASE WHEN regexp_matches(user_agent, 'python|curl|okhttp|Go-http') THEN 1 ELSE 0 END AS scripted_ua,
    lag(lat) OVER acct AS plat, lag(lon) OVER acct AS plon, lag(ts) OVER acct AS pts, lat, lon,
    hour(ts) AS hour_utc
  FROM l
  WINDOW ip1h AS (PARTITION BY ip ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW),
         asn1h AS (PARTITION BY asn ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW),
         acct1h AS (PARTITION BY account_id ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW),
         pw6h AS (PARTITION BY pw_hash ORDER BY ts RANGE BETWEEN INTERVAL 6 HOUR PRECEDING AND CURRENT ROW),
         acct AS (PARTITION BY account_id ORDER BY ts))
SELECT *,
  ip_fail_1h / ip_attempts_1h::DOUBLE AS ip_fail_ratio_1h,
  coalesce(2 * 6371 * asin(sqrt(pow(sin(radians(lat - plat) / 2), 2) +
     cos(radians(plat)) * cos(radians(lat)) * pow(sin(radians(lon - plon) / 2), 2))), 0) AS km_from_prev,
  coalesce(2 * 6371 * asin(sqrt(pow(sin(radians(lat - plat) / 2), 2) +
     cos(radians(plat)) * cos(radians(lat)) * pow(sin(radians(lon - plon) / 2), 2)))
     / greatest(epoch(ts - pts) / 3600.0, 0.05), 0) AS kmh_from_prev
FROM f
ORDER BY ts
"""


def login_features(con) -> pd.DataFrame:
    df = con.execute(SQL).df()
    df["y"] = (df["attack"] != "").astype(int)
    return df
