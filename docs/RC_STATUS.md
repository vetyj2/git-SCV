# Git-SCV v0.3 RC Status

This document records the current v0.3 release-candidate state against the
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

## Missing Before Stable

- Full parser coverage for every ecosystem in the original long-range plan.
- Full package-manager/download-path expansion.
- Advanced interactive graph layout beyond the current basic HTML viewer.
- Real gate-decision approval CLI lifecycle beyond the current source-bound
  decision artifact and `next-action` blocker.
- Hard performance budgets in CI; current metrics are acceptance guidance.

## Public Release Blockers

The tree must not be released if any item in `docs/RC_BLOCKERS.md` is present.
At minimum, release requires `cargo fmt`, `cargo test`, `cargo clippy
--all-targets`, schema JSON validation, script syntax validation, and package
verification to pass.
