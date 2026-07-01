# Changelog

## 0.3.2 - 2026-07-02

- Added short guided entrypoints: `git-scv init`, `git-scv doctor`, and
  `git-scv <repo-path-or-github-url>`. The default non-interactive quick flow
  performs a pre-install manual check and avoids paid worker invocation unless
  full screening is explicitly selected.
- Added Codex-first first-run onboarding and root `doctor` notices for
  OAuth/token non-access, API-key paid-usage risk, worker CLI model/thinking
  confirmation, built-in Codex/Claude linkage, and remediation hints.
- Added `scripts/git-scv-worker-adapter.example.py` as a non-secret adapter
  template for custom coding-agent CLIs, with script verification inventory and
  traceability coverage.
- Updated README, USAGE, Hermes guidance, RC acceptance, RC blockers, RC status,
  CLI spec, release docs, dashboard text, and install commands for the v0.3.2
  public release line.
- Added RC flow tests for `init`, root `doctor`, and the short repo command
  defaulting to pre-install manual check without auth-file access.

## 0.3.1 - 2026-07-01

- Added the v0.3 RC analysis orchestrator flow: `review`, `continue`,
  persistent analysis jobs, work-order binding, safe content export, and
  Codex invocation receipts.
- Added one-touch `scan` orchestration with manual, fake, Codex, and Claude
  worker backend selection, source-bound sequential job execution, terminal
  progress modes, and final report generation after completed runnable jobs.
- Added `worker doctor` for auth-file-free worker CLI readiness checks and
  `clean` for safe run-internal temporary analysis export cleanup.
- Added a dedicated allowlisted worker process boundary so Git-SCV can invoke
  configured Codex/Claude worker CLIs without allowing target repository
  commands or OAuth/token file inspection.
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
