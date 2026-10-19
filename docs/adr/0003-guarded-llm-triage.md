# ADR 0003: LLM triage behind a grounding guard

**Status:** accepted

**Context.** An LLM can summarise an incident and propose a response quickly, but it
can also invent evidence, recommend actions that do not exist, or be steered by text
an attacker placed in a log field (a user agent, for example).

**Decision.** The model only gets read-only tools (evidence, entity history, IP
context, playbook search). A guard checks every answer: cited event IDs must have been
returned by a tool, action IDs must come from a playbook section the model retrieved,
and the attack type must be a known one. Any failure, timeout or quota error falls
back to a deterministic triage built from the rule metadata.

**Consequences.** The worst case is the deterministic answer, never a fabricated one.
The cost is that a correct but unusual recommendation outside the playbooks is rejected;
the fix for that is to add it to the playbook, which is reviewed like code.
