# Git-SCV v0.3.4 RC Status

This document records the current v0.3.4 release-candidate state against the
2026-06-29 no-exec, no-leak, source-bound agent orchestration plan.

## Implemented

- artifact-contract-v2 metadata on generated JSON artifacts.
- Redacted `run.json.command` with `raw_args_stored:false`.
- Redacted evidence excerpts with command-like raw values excluded.
- Artifact leak validation across JSON, Markdown, HTML, partial/failure output,
  and validation output.
- Source fingerprinting and `git-scv case verify-source`.
- Path privacy with default `repo-relative` output.
- Local inspect limits and snapshot archive limits in coverage/source artifacts.
- Artifact manifest hash chain and post-write validation.
- Split gates for sensitive raw review, execution model-input review, and
  execution command review.
- Permission fields and safe-claim prohibition in review/security/brief.
- First-class `brief.json` and `brief.md` with actionability fields.
- Agent receipt creation bound to artifact manifest and source fingerprint.
- Rust case CLI for create/list/show/brief/status/verify-source/delete/prune/doctor.
- `git-scv case next-action` for source, manifest, receipt, and gate blocking.
- Dependency provenance minimum and supported surface matrix.
- Prompt-injection surface detection as untrusted target-repo text.
- Connection graph, reachability scenarios, architecture map, relation map,
  source landmarks, visualization index, analysis plan, cross-unit analysis,
  synthesis, and follow-up artifacts.
- Default `architecture.html` basic viewer with overview, execution scenarios,
  script relationships, gates, coverage, landmarks, and synthesis views.
- Unit-analysis validation and synthesis/follow-up CLI.
- Hermes wrapper cleanup delegated to Rust case delete/prune.
- Public `git-scv review <repo-path> --goal <goal>` entrypoint for the
  preflight plus slice-analysis workflow.
- Public `git-scv scan <repo-path> --goal <goal> --worker <backend>` entrypoint
  for one-touch preflight, sequential worker slice analysis, validation, and
  final report generation.
- Public `git-scv init` first-run readiness check with Codex-first guidance,
  OAuth/token non-access policy, API-key cost warning, model/thinking-level
  reminder, worker readiness, adapter-template pointer, and next safe command.
- Public `git-scv doctor` readiness check for the short entry command,
  built-in Codex/Claude/fake/manual linkage, auth-file boundary, remediation
  hints, and worker readiness state.
- Public short entrypoint `git-scv <repo-path-or-github-url>` with guided
  quick flow. Non-interactive local paths default to `local-preflight`; GitHub
  URLs default to `web-metadata-preflight` with `code_body_analysis:false`,
  `worker_started:false`, and `semantic_analysis_complete:false`.
- Interactive quick-start selection supports Up/Down and `j`/`k` movement,
  Enter confirmation, direct `1`-`3` choice, and numbered-prompt fallback when
  raw terminal selection is unavailable.
- GitHub `pinned-snapshot` scan mode resolves refs to commit SHA, downloads the
  pinned archive, records a self-observed SHA-256, labels the verification
  level as `pinned-commit-self-observed`, and continues into the local
  source-bound worker workflow.
- `git-scv worker doctor --backend <backend>` readiness checks using worker CLI
  exit status and redacted output only, without OAuth/token file access.
- Allowlisted worker process boundary for Codex/Claude/fake workers, with
  target-repository executable and cwd rejection.
- Example custom worker adapter template at
  `scripts/git-scv-worker-adapter.example.py`, documented as a non-secret
  command-shape template that must be copied outside target repositories.
- `git-scv clean <run-dir>` dry-run by default and exact-ack cleanup for
  run-internal temporary analysis exports only.
- Public `git-scv continue <run-dir>` entrypoint that resumes progress and
  writes the final user report only after runnable jobs are done.
- Source-bound `work_order_binding.json` plus `analysis_jobs.jsonl` and
  `codex_invocation_receipt.jsonl`.
- Worker prompt/schema/validator alignment for unit-analysis contract fields,
  plus one-step format/schema repair retry.
- Worker attempt receipts are written for attempt start, process failure,
  schema failure, repair, and success without raw prompt/stdout/stderr storage.
- Qualitative digests, map deltas, relation candidates, and follow-up jobs are
  aggregated into `analysis_map.json`, `analysis_followup_jobs.jsonl`, and the
  final user report.
- Analysis job CLI for list/next/claim/complete/fail and safe content export.
- Local runtime source pointer separated from public artifacts so default
  repo-relative path privacy can coexist with later content export.
- Stale-source blocking for job claim, content export, and job completion.
- Terminal progress output with stage, source status, gate status, job counts,
  current job/path, failed/blocked counts, final-report status, no-exec status,
  and next safe command.
- GitHub pinned snapshot defaults to codeload zip archives, while tar fallback
  skips safe archive metadata and continues to reject unsafe entries.
- GitHub `web-selected-preflight` reads only allowlisted public body files,
  records limited code-body analysis, redacts excerpts, and does not start a
  worker or claim semantic completion.
- Worker output contract v2.1 requires qualitative digest, map delta,
  relation/follow-up candidates, and scoped abstentions while rejecting generic
  low-value boilerplate.
- Codex/Claude worker budget gate records a sample estimate and requires exact
  `continue-worker-budget` approval before larger runs.
- Dynamic follow-up jobs are promoted into the worker queue with automatic
  follow-up depth capped; unresolved follow-up blocks final report completion.
- `final_user_report.md/html` now uses a 15-section user report structure.
- Runtime `architecture.html` refreshes after worker/follow-up/budget/final
  state changes and shows worker progress, budget gate, follow-up queue, and
  unresolved relation status.
- `cleanup_manifest.json` records Git-SCV-owned cleanup candidates, never-touch
  auth/token policy, and no raw absolute local source paths.
- TTY dashboard uses a compact three-line `SCV[...]` frame with report/map and
  cleanup pointers.

## Documented

- Threat model, artifact contract, approval gates, case packages, supported
  surfaces, security model, release discipline, future package-manager scope,
  Hermes rules, RC acceptance, blockers, visualization, architecture maps, and
  script relationships.

## Tested

- No-exec sentinel fixture.
- Artifact leak regression for URL query/fragment/token-like markers and
  lifecycle command redaction.
- Failure-path redaction for snapshot validation failures.
- HTML report escaping and architecture HTML escaping/no-network/no-target-JS.
- Source fingerprint stale-source detection.
- Case delete/prune safety constraints.
- `case next-action` blocking for missing receipt, execution gate, exact command
  envelope, and stale source.
- Script wrapper contract against direct deletion and target package-manager
  execution.
- Integration contract for the full RC artifact set.
- `review -> analysis job claim -> export-content -> complete -> continue`
  end-to-end flow.
- `scan --worker fake` one-touch flow through final report generation.
- `git-scv init --worker fake --strict` reports readiness and cost/auth/model
  notices without auth-file access.
- `git-scv doctor --backend fake --strict` reports built-in linkage,
  remediation surface, and readiness without auth-file access.
- `git-scv <repo-path>` defaults to pre-install manual check in non-interactive
  contexts.
- Rejection of worker executables located inside the target repository.
- Source change after review blocks job claim and marks analysis state stale.
- Bulk `analysis import` completes only matching jobs and keeps final report
  blocked while runnable jobs remain.

## Missing Before Stable

- Full parser coverage for every ecosystem in the original long-range plan.
- Full package-manager/download-path expansion.
- Advanced interactive graph layout beyond the current basic HTML viewer.
- Real gate-decision approval CLI lifecycle beyond the current source-bound
  decision artifact and `next-action` blocker.
- Hard performance budgets in CI; current metrics are acceptance guidance.
- Advanced Codex/Claude adapter compatibility. The RC has an allowlisted
  `scan --worker codex|claude` process boundary, but real CLI argument shapes
  may require `GIT_SCV_CODEX_WORKER_ARGS` or `GIT_SCV_CLAUDE_WORKER_ARGS` on
  machines whose local worker CLI differs from the default shell-free command.

## Public Release Blockers

The tree must not be released if any item in `docs/RC_BLOCKERS.md` is present.
At minimum, a GitHub tag release requires `cargo fmt`, `cargo test`, `cargo
clippy --all-targets`, schema JSON validation, script syntax validation, secret
scan, version consistency, and a fresh `cargo install --git ... --tag v0.3.4
--locked` test after tagging. `cargo package --locked` is recommended for the
GitHub tag release and required before any crates.io publish path.
