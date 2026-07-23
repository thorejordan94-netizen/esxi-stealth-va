# Contextual Reporting

The contextual reporting layer does not call an external AI service. It uses a local deterministic knowledge base so reports remain reproducible and usable in isolated environments.

## Matching order

Each normalized finding is scored against the hardcoded scenarios in `orchestrator/finding_knowledge.py`:

1. exact scanner or template identifier;
2. title, description, and evidence keywords;
3. scanner tags;
4. finding category;
5. severity-specific generic fallback.

Exact identifiers receive the strongest weight. The selected context records its rule ID, match score, and confidence in JSON and Markdown.

## Context fields

Each contextual finding contains:

- conclusion;
- practical implications;
- likelihood statement;
- remediation measures;
- validation and closure criteria;
- priority;
- optional control mappings and references;
- raw scanner evidence.

Unknown scenarios use a conservative generic fallback. They are not assigned fabricated fixed versions, prerequisites, or CVE details.

## Extending the knowledge base

Add a `_rule(...)` entry to `KNOWLEDGE_BASE`. Prefer exact IDs where the scanner provides stable identifiers, then include narrowly scoped keywords and tags. Remediation must be vendor-neutral unless the rule is explicitly tied to a vendor advisory already provided by scanner evidence.

Add a regression case to `tests/test_contextual_reporting.py` for every new exact-ID rule.
