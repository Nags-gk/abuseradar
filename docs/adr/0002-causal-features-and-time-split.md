# ADR 0002: Causal features and a time-based split

**Status:** accepted

**Context.** A random train/test split on event data leaks the future: the model sees
part of a campaign in training and the rest in testing, and scores look better than
they would in production.

**Decision.** Every feature is a SQL window that ends at the current event (a test
asserts that adding later events never changes an earlier login's features). The model
trains on days 0-9 and is scored on days 10-20. The decision threshold is chosen from
out-of-fold predictions on the training days. The test window contains a
low-and-slow credential-stuffing variant that never appears in training.

**Consequences.** Reported numbers are what a model trained last week would do this
week. The evasive campaign gets 72% login-level recall, which is reported as is rather
than hidden by an average.
