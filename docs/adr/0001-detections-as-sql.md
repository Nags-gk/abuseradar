# ADR 0001: Detections as SQL in YAML

**Status:** accepted

**Context.** Detections change faster than code. Analysts need to read, review and
tune them without learning the engine, and each rule needs metadata (ATT&CK mapping,
false positives, response) next to its logic.

**Decision.** Each rule is a YAML file with one SQL query that returns a fixed set of
columns (entity, window, evidence IDs, metric, detail). DuckDB runs them over Parquet.
The same SQL runs on BigQuery with minor dialect changes (`time_bucket` becomes
`TIMESTAMP_BUCKET`).

**Consequences.** Adding a rule is one file and one test. Rules are reviewable in a
pull request and their precision is tracked in CI. Logic that needs state across
long periods (graph rings, model scores) lives in Python layers instead.
