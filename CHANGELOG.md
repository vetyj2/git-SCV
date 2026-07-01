# Changelog

## 0.3.1 - 2026-07-01

- Added the v0.3 RC analysis orchestrator flow: `review`, `continue`,
  persistent analysis jobs, work-order binding, safe content export, and
  Codex invocation receipts.
- Added GitHub URL review planning for metadata-only remote preflight without
  cloning or executing the target repository.
- Bound slice claim/export/complete/finalization paths to current source
  fingerprint and artifact manifest validity.
- Added orchestrator schemas for analysis jobs, content export, work-order
  binding, and Codex invocation receipts.
- Updated RC docs, Hermes guidance, and release contracts for the brief-first
  slice-analysis workflow.
- Updated public release documentation to prefer tag-based `v0.3.1` install
  commands and treat `cargo package` as recommended for GitHub tag releases,
  required for crates.io release paths.
- Updated public spec/dashboard artifact counts to the current 45-file RC
  artifact set.
- Removed production clippy `too_many_arguments` warnings with small internal
  input/context structs while preserving artifact and CLI behavior.

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
