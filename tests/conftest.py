import itertools

import pandas as pd
import pytest

from abuseradar import store
from abuseradar.sim import COLUMNS

_ids = itertools.count()
T0 = pd.Timestamp("2026-09-10T12:00:00Z")


def ev(minutes=0.0, **kw):
    """One event with benign defaults; override any column."""
    row = dict(ts=T0 + pd.Timedelta(minutes=minutes), event_type="login", account_id="a00001", ip="10.0.0.1",
               asn=64512, lat=37.0, lon=-122.0, device_fp="fp-home", user_agent="HomeApp/5.2 iOS", success=True,
               pw_hash="", device_id="", endpoint="", status=200, label="", attack="")
    row.update(kw)
    return row


def make_con(rows, accounts=("a00001", "a00002", "a00003")):
    df = pd.DataFrame(rows)
    asn_type = df["asn_type"] if "asn_type" in df else "residential"
    for c in COLUMNS:
        if c not in df:
            df[c] = ev()[c]
    df = df[COLUMNS].assign(asn_type=asn_type).sort_values("ts").reset_index(drop=True)
    df.insert(0, "event_id", range(len(df)))
    df["country"] = "US"
    con = store.connect()
    store.load_frames(con, df, pd.DataFrame({"account_id": list(accounts)}))
    return con


@pytest.fixture
def mk():
    return make_con
