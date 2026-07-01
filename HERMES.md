# Git-SCV Hermes Harness Guide

This guide is for Hermes-style coding agents that use Git-SCV as a preflight
repository inspection tool.

Git-SCV core does not spawn or authenticate a model. It creates deterministic
artifacts and a source-bound analysis job queue that an active Codex/Hermes
session can consume one slice at a time before deciding whether install, build,
test, run, model input, or user approval is appropriate.

OAuth/API/connector credentials remain only in the user's terminal, Codex, or
connector session. Git-SCV must not request, read, store, forward, serialize, or
write those credentials into the repository, run directory, artifacts, stdout,
or stderr.

## Install Or Update Git-SCV

Install the current tagged GitHub release:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked
```

Update to the current tagged GitHub release:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked --force
```

Install a specific reviewed revision:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --rev <commit-sha> --locked --force
```

Installing from a moving branch is an advanced, unstable bootstrap path and
should not be the default Hermes recommendation.

Check the installed binary:

```sh
git-scv --version
git-scv --help
```

## Optional Harness Script

If this repository is checked out locally, Hermes can use:

```sh
scripts/git-scv-hermes.sh commands
```

The script is a thin convenience wrapper. It does not make safety decisions and
does not call a model. It only:

- installs, updates, or uninstalls the `git-scv` binary
- creates per-case temporary inspection packages
- runs `git-scv inspect` or `git-scv snapshot`
- prints the mandatory compact `git-scv brief` output after inspection
- prints the report and JSON artifact paths Hermes should read
- removes one case package or the whole local case root on request

For the newer slice-review runtime, prefer the Rust CLI directly:

```sh
git-scv review <repo-path> --goal install
git-scv continue <run-dir>
```

Hermes/Codex then processes the internal queue with:

```sh
git-scv analysis job claim <run-dir> --agent Codex
git-scv analysis export-content <run-dir> --job <job-id>
git-scv analysis job complete <run-dir> --job <job-id> --result <unit.jsonl>
```

Those commands verify the work-order binding and source fingerprint before
content export or completion. If the source changed, stop and re-run
`git-scv review`.

The default case root is:

```text
${TMPDIR:-/tmp}/git-scv-cases
```

Override it when needed:

```sh
GIT_SCV_CASE_ROOT=/path/to/cases scripts/git-scv-hermes.sh inspect <repo-path>
```

## User Intent To Hermes Command

| User intent | Hermes action |
| --- | --- |
| "Install Git-SCV" | `scripts/git-scv-hermes.sh install` or `cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked` |
| "Update Git-SCV" | `scripts/git-scv-hermes.sh update-latest` or `cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked --force` |
| "Inspect this local repo" | `scripts/git-scv-hermes.sh inspect <repo-path> [label]` |
| "Inspect this verified archive" | `scripts/git-scv-hermes.sh snapshot <archive-url> <sha256> [label]` |
| "Summarize the mandatory safety gate" | `scripts/git-scv-hermes.sh brief <case-dir>` |
| "Show me the report paths again" | `scripts/git-scv-hermes.sh show <case-dir>` |
| "Delete this report package" | `scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case` |
| "Delete all Git-SCV report packages" | `scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases` |
| "Uninstall Git-SCV" | `scripts/git-scv-hermes.sh uninstall` and optionally `scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases` |

## Per-Repository Report Package

For local repository inspection:

```sh
scripts/git-scv-hermes.sh inspect <repo-path> [label]
```

The script prints key-value paths such as `case_dir=...`, `run_dir=...`,
`report_md=...`, `brief_command=...`, and `cleanup_command=...`. It then prints
the mandatory compact `git-scv brief` output so the agent sees verdict,
required actions, default model exclusions, and gated slice counts before any
long report can be skipped. A normal local case looks like:

```text
<case-dir>/
  run/
    run.json
    source.json
    inventory.json
    coverage.json
    evidence.json
    findings.json
    dependencies.json
    sectors.json
    sensitive.json
    gates.json
    slices.json
    static_preflight_summary.json
    sub_slices.json
    sub_slices.jsonl
    analysis_inputs.json
    analysis_inputs.jsonl
    analysis_state.json
    analysis_events.jsonl
    llm_backend.json
    gpt_work_order.json
    gpt_work_order.md
    work_order_binding.json
    analysis_jobs.jsonl
    codex_invocation_receipt.jsonl
    review.json
    security.json
    supported_surfaces.json
    gate_decisions.json
    connection_graph.json
    reachability_scenarios.json
    architecture_map.json
    relation_map.json
    source_landmarks.json
    visualization_index.json
    analysis_plan.json
    analysis_map.json
    cross_unit_analysis.json
    synthesis.json
    followup_plan.json
    artifact_manifest.json
    brief.json
    brief.md
    report.md
    report.html
```

For snapshot inspection:

```text
<case-dir>/
  snapshot/
    source/
    run/
      ...same inspect artifacts...
```

After the user has reviewed the report and wants to discard the evidence
package:

```sh
scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case
```

To remove every local Git-SCV case package under the configured case root:

```sh
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

## Mandatory Briefing Contract

Hermes must treat `git-scv brief <run-dir>` or
`scripts/git-scv-hermes.sh brief <case-dir>` as the first gate after inspection.

The brief output is not a proof that the whole report was read. It is a compact
guardrail that makes omission visible. Before any model input, command
execution, install, build, or cleanup decision, Hermes must tell the user:

- `verdict`
- `action_required`
- every required action id
- sensitive and execution candidate counts
- default model excluded path count
- the `agent_read_receipt` line

If Hermes cannot produce that summary, it must stop and re-run the brief command.

## Artifact Reading Contract

After the mandatory brief, Hermes should read the artifacts in this order:

1. `run.json`
2. `security.json`
3. `review.json`
4. `gates.json`
5. `sensitive.json`
6. `slices.json`
7. `report.md` or `report.html`

`security.json` is the first-pass machine summary. `review.json` contains the
verdict, counts, required actions, and default model excluded paths. `gates.json`
and `slices.json` decide what may be sent to a model.

## Model Input Rules

Hermes may send file contents to a model only after checking `slices.json` or,
preferably, after claiming an `analysis_jobs.jsonl` job and exporting that
job's allowed content range with `git-scv analysis export-content`.

- Use only files with `default_model_input=true` by default.
- Do not send sensitive candidates to a model unless the user gives the required
  two-step approval and exact acknowledgement strings.
- Do not send automatic-execution or execution-related candidates to a model
  before showing their paths to the user and receiving approval.
- Treat `oversized-slice-review` as a planning warning, not a safety verdict.
- Process one claimed job at a time. Write a unit-analysis JSON/JSONL result,
  complete the job, and let Git-SCV record `codex_invocation_receipt.jsonl`
  with `oauth_token_stored:false` and `target_repo_commands_executed:false`.

## Execution Rules

Hermes must not run install, build, test, script, hook, binary, or container
commands from the inspected repository before explicit user approval.

Git-SCV findings are review prompts, not proof of safety or proof of harm.

## Clean Uninstall

Remove the installed binary:

```sh
cargo uninstall git-scv
```

Remove all local Git-SCV case packages:

```sh
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

Git-SCV does not create background services, shell hooks, git hooks, or global
configuration. It writes inspection artifacts only to the output directories
chosen by the user or by the harness script.
