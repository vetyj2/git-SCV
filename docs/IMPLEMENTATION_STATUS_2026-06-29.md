# Git-SCV v0.3 Implementation Status

This status note records how the 2026-06-29 final patch plan is reflected in
the current tree.

## Completed Contract Layers

- P0 no-leak foundation: shared redaction layer, redacted run command contract,
  redacted evidence excerpts, artifact leak scan V25, source fingerprint,
  local and snapshot limits, path privacy, failure-path redaction, artifact
  manifest hash chain, HTML escaping tests, and no-exec sentinel tests.
- P1 agent protocol: split gates, permission fields, brief artifacts, receipt
  binding, source verification, Rust case CLI, public docs, schemas, release
  files, and tag/rev install docs.
- P1.5 utility layer: dependency provenance minimum, prompt-injection surface
  detection, and supported surface/capability matrix.
- P3/P3.5/P4 orchestration layer: connection graph, reachability scenarios,
  architecture map, relation map, source landmarks, visualization index,
  default `architecture.html`, analysis plan, minimal cross-unit analysis,
  synthesis, follow-up plan, and `validate-unit` / `validate-units` /
  `synthesize` / `followup-plan` / `validate-followup` CLI commands.
- Actionability layer: `brief.json`/`brief.md` point to `architecture.html`,
  record next safe commands and do-not-do-yet commands, and
  `git-scv case next-action` checks source, manifest, receipt, exact argv, and
  gate blockers before any next action.

## Parser And Package-Manager Boundary

The current parser expansion is intentionally conservative.

- npm `package.json` scripts and direct dependency source kinds are parsed.
- Expanded ecosystem files such as GitHub Actions, Dockerfile/Containerfile,
  Cargo, Python, Go, Ruby, Makefile-like automation, shell/config files, hooks,
  and pre-commit files are detected as surfaces.
- Name-detected or unsupported execution surfaces set
  `verdict_effect: "insufficient-coverage"` and add
  `unsupported-surface-name-detected` to review reason codes. Git-SCV does not
  claim `no-blocker-observed` for those cases.
- Raw command bodies, raw dependency specs, tokenized URLs, and sensitive raw
  content are not stored. The same contract applies to `architecture.html`.

P5 package-manager/download-path expansion remains a documented future layer in
`docs/FUTURE_PACKAGE_MANAGERS.md`. The implemented contract keeps the P5
boundary explicit: Git-SCV still does not run package managers, `curl | sh`,
install scripts, builds, tests, containers, or target repository commands.

## Verification

Latest verification run:

- `cargo fmt`
- `cargo test`
- `cargo clippy --all-targets` (exit code 0; existing warning-level lint output
  remains for test `unwrap`/`expect` usage and a few long helper signatures)
- `jq empty schemas/*.json`
- `bash -n scripts/git-scv-hermes.sh`
- `cargo package --locked --allow-dirty`

## Non-Claims

Git-SCV still does not prove malware absence, install safety, execution safety,
semantic truth of agent analysis, or complete transitive dependency review.
