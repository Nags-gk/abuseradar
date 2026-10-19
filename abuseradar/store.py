"""DuckDB storage. Events live in Parquet; every detector reads the same `events` view."""
from __future__ import annotations

from pathlib import Path

import duckdb
import pandas as pd

DATA = Path(__file__).resolve().parent.parent / "data"


def connect(path: str | Path = ":memory:") -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(path))
    con.execute("SET TimeZone = 'UTC'")
    return con


def load_frames(con, events: pd.DataFrame, accounts: pd.DataFrame | None = None):
    con.register("_ev", events)
    con.execute("CREATE OR REPLACE TABLE events AS SELECT * FROM _ev")
    con.unregister("_ev")
    ids = accounts if accounts is not None else pd.DataFrame({"account_id": []})
    con.register("_acc", ids[["account_id"]])
    con.execute("CREATE OR REPLACE TABLE accounts AS SELECT * FROM _acc")
    con.unregister("_acc")


def load_parquet(con, data_dir: Path = DATA):
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet('{data_dir / 'events.parquet'}')")
    con.execute(f"CREATE OR REPLACE VIEW accounts AS SELECT * FROM read_parquet('{data_dir / 'accounts.parquet'}')")
