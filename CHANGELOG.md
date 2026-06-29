# Changelog

## 0.3.0

- Added artifact-contract-v2 manifest, first-class brief artifacts, source
  fingerprinting, path privacy, artifact leak scanning, and local inspect
  limits.
- Split gates into sensitive raw review, execution model-input review, and
  execution command review.
- Added permission fields, allowed verdict vocabulary, agent receipt creation,
  and case package CLI.
- Strengthened redaction for command arguments, URL queries/fragments, package
  lifecycle evidence, and failure paths.
- Added graph, analysis plan, cross-unit synthesis, synthesis, follow-up, and
  unit-analysis validation artifacts for the agent review loop.
- Added default architecture visualization artifacts:
  `architecture.html`, `architecture_map.json`, `relation_map.json`,
  `source_landmarks.json`, `visualization_index.json`,
  `reachability_scenarios.json`, `supported_surfaces.json`, and
  `gate_decisions.json`.
- Added `git-scv case next-action` to bind requested next actions to current
  source status, artifact manifest, agent receipt, exact argv, and gate state.
- Added script verification docs and tests that bind helper scripts to REQ
  documents, user intent, and the 2026-06-29 security plan.
