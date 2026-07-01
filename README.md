# Git-SCV

Git-SCV means Source-code-voyager.

Git-SCV is a Rust CLI for no-exec repository inspection. It is intended to help
users and coding agents review an unfamiliar repository before installing,
building, testing, or running it.

Git-SCV reports what it observed, what evidence supports each finding, and what
it did not inspect. It does not prove that a repository is safe.

## Install

Install Rust first:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install Git-SCV from GitHub:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked
cargo install --git https://github.com/vetyj2/git-SCV --rev <commit-sha> --locked
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.3 --locked --force
git-scv --version
```

Installing from a moving branch is an advanced, unstable bootstrap path:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --locked
```

Or install it from a local checkout:

```sh
cargo install --path . --locked
```

## Build

```sh
cargo build
```

## Usage

```sh
git-scv init
git-scv doctor
git-scv <repo-path-or-github-url>
git-scv scan <repo-path> --goal install --worker codex
git-scv scan <repo-path> --goal install --worker manual
git-scv scan https://github.com/<owner>/<repo> --mode web-metadata-preflight
git-scv scan https://github.com/<owner>/<repo> --mode pinned-snapshot --worker codex
git-scv worker doctor --backend codex
git-scv review <repo-path> --goal install
git-scv review https://github.com/<owner>/<repo> --goal install
git-scv continue <run-dir>
git-scv inspect <repo-path> --out <run-dir>
git-scv snapshot <archive-url> --out <snapshot-dir> --sha256 <hex>
git-scv brief <run-dir>
git-scv receipt create <run-dir> --agent Hermes --summary-file <summary.md> --summarized-to-user --blocked-actions-acknowledged
git-scv case create <repo-path>
git-scv case verify-source <case-id>
git-scv watch <run-dir>
git-scv analysis job claim <run-dir> --agent Codex
git-scv analysis export-content <run-dir> --job <job-id>
git-scv analysis job complete <run-dir> --job <job-id> --result <unit.jsonl>
git-scv analyze <run-dir> --backend manual-export
git-scv analysis import <run-dir> <unit-results.jsonl>
git-scv report final <run-dir>
git-scv github plan https://github.com/<owner>/<repo> --ref <sha-or-tag> --out <plan-dir>
git-scv clean <run-dir>
```

The terminal is the compact control surface, not the detailed report. During
long scans Git-SCV shows the current stage, progress, current job/path, blocked
or failed counts, and the next safe command. Detailed evidence, architecture
relationships, and repo-owner feedback stay in `brief.md`,
`final_user_report.md`, and `architecture.html`.

Run `git-scv init` once before full screening. Git-SCV is Codex-first by
default in its recommended workflow, but it does not read Codex OAuth/token
files. The init/doctor output reminds users that the worker CLI's current model
and thinking/reasoning level will be used, and that API-key based worker
configuration can incur paid usage. If you use Claude or another coding agent,
copy [`scripts/git-scv-worker-adapter.example.py`](scripts/git-scv-worker-adapter.example.py)
outside the target repository and adjust the non-secret CLI command/args.

The shortest preflight entry is:

```sh
git-scv https://github.com/<owner>/<repo>
```

In an interactive terminal, the short entry opens a three-option quick-start
menu. Use Up/Down or `j`/`k` to move, Enter to confirm, or `1`-`3` to choose
directly. Non-interactive runs keep the safe default and never start a paid
worker implicitly.

For GitHub URLs this starts `web-metadata-preflight` in non-interactive use:
Git-SCV reads GitHub tree metadata only, reports `code_body_analysis=false` and
`worker_started=false`, and does not claim semantic code analysis completion.
Use `--mode pinned-snapshot` to resolve a GitHub ref to a commit SHA, download
that commit archive, record a self-observed SHA-256, and continue into the
normal source-bound scan workflow. This is not independent external checksum
verification; strict verification remains the `snapshot --sha256 <hex>` path.
For local directories the short command starts the local preflight path without
invoking a paid worker by default.

`<repo-path>` must be a local directory for full slice review. `review` accepts
GitHub repository URLs only for a no-exec metadata plan; it does not fetch file
bodies, clone, or claim semantic analysis completion. Repository URL inputs such
as `https://...`, `git@host:owner/repo.git`, and `file://...` are rejected by
`inspect`. Download or clone the repository first, then inspect that local
directory.

The `inspect` command never fetches from a remote. The separate `snapshot`
command downloads an HTTPS archive in memory, checks it against a user-provided
SHA-256 digest, and extracts only safe `.zip`, `.tar.gz`, or `.tgz` entries into
`<snapshot-dir>/source`, then writes the normal inspection artifacts to
`<snapshot-dir>/run`. Its `--sha256` value must be a 64-character hex SHA-256
digest, its URL must start with `https://`, it must not include URL user
information, and its output directory must be new or empty. URL validation errors
redact user information and query or fragment details. Snapshot inspection writes
sanitized snapshot metadata to `run/source.json`, including the archive URL
without query or fragment details, the verified SHA-256 digest, archive format,
and extracted source path.

For detailed command examples, sensitive-candidate modes, and artifact reading
order, see [USAGE.md](USAGE.md).

`scan` is the one-touch entrypoint. It runs no-exec preflight, writes the work
order, creates source-bound analysis jobs, optionally invokes a configured
Codex/Claude worker CLI one slice at a time, validates each unit-analysis
result, retries one formatting/schema error by default, writes non-empty
attempt receipts, and creates the final user report only after runnable jobs
are completed. Qualitative digests, map deltas, relation candidates, and
follow-up jobs from validated unit analyses are folded into `analysis_map.json`
and `final_user_report.md/html`. `review` remains the split/manual entrypoint
for agents that want to claim/export/complete jobs themselves. `inspect`,
`snapshot`, and `github plan` remain core preflight commands.

Git-SCV never runs target repository package managers, shells, scripts, hooks,
binaries, workflows, containers, or install commands. The only process-spawning
exception is the allowlisted worker CLI boundary used by `scan --worker
codex|claude|fake`; it is not allowed to point inside the target repository.
`worker doctor` infers readiness from worker CLI exit status and redacted
stdout/stderr only. It must not stat, list, read, hash, delete, write, or
serialize Codex/Claude OAuth token files or auth directories.

For manual review, `analysis job claim`, `analysis export-content`, and
`analysis job complete` give an active Codex/user terminal session
deterministic slice work, redacted content export, and source-bound completion
receipts. `report final` is blocked while runnable jobs remain queued, claimed,
or failed.

When an automated LLM CLI backend is unavailable, Git-SCV still writes
`gpt_work_order.json` and `gpt_work_order.md` as a source-bound receipt so GPT
or another agent can continue the ordered job/manual-export, unit-analysis, and
final-report workflow without pretending preflight is complete analysis.
Codex OAuth or similar agent credentials stay in the user's terminal or agent
session. Git-SCV must not request, read, store, forward, or serialize OAuth
tokens in the repository, run directory, artifacts, stdout, or stderr.

For Hermes-style agent integration, per-repository temporary report packages,
cleanup commands, and install/update/uninstall commands, see
[docs/HERMES.md](docs/HERMES.md). A convenience wrapper is available at
[`scripts/git-scv-hermes.sh`](scripts/git-scv-hermes.sh).
The v0.3 implementation boundary is summarized in
[docs/IMPLEMENTATION_STATUS_2026-06-29.md](docs/IMPLEMENTATION_STATUS_2026-06-29.md).

The output directory must be new or empty. Git-SCV does not execute install,
build, test, script, hook, binary, or container commands from the inspected
repository.

When Git-SCV records git remote URLs in `source.json`, URL user information is
redacted so access tokens are not copied into artifacts.

The run directory contains machine-readable artifacts and a human-readable
report:

```text
run.json
artifact_manifest.json
brief.json
brief.md
source.json
inventory.json
coverage.json
evidence.json
findings.json
dependencies.json
sectors.json
sensitive.json
gates.json
gate_decisions.json
slices.json
static_preflight_summary.json
sub_slices.json
sub_slices.jsonl
analysis_inputs.json
analysis_inputs.jsonl
analysis_state.json
analysis_events.jsonl
llm_backend.json
source_acquisition.json (created by `git-scv scan --mode pinned-snapshot`)
worker_backend.json (created by `git-scv scan --worker <backend>`)
gpt_work_order.json
gpt_work_order.md
work_order_binding.json
analysis_jobs.jsonl
codex_invocation_receipt.jsonl
analysis_followup_jobs.jsonl
review.json
security.json
supported_surfaces.json
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
agent_receipt.json (created after `git-scv receipt create`)
report.md
report.html
architecture.html
final_user_report.md (created after completed analysis jobs)
final_user_report.html (created after completed analysis jobs)
```

## Recommended Use

Use Git-SCV before installing, building, testing, or running an unfamiliar
repository.

1. Use `git-scv scan <repo-path> --goal install --worker codex` when the
   repository is already on disk and you want one command to run preflight,
   sequential worker slice analysis, and final report generation.
2. Use `git-scv scan <repo-path> --goal install --worker manual` or
   `git-scv review <repo-path> --goal install` when Codex/Claude CLI is not
   available or you want an agent to handle each job explicitly.
3. Use `inspect` when you only need the static preflight artifact set.
4. Use `snapshot` only when you have an HTTPS archive URL and a SHA-256 digest
   verified through a separate channel.
5. Run `git-scv brief <run-dir>` first and summarize its verdict, required
   actions, model-excluded path count, `artifact_manifest_sha256`,
   `source_fingerprint_hash`, and `agent_read_receipt` before any next action.
6. Open `architecture.html` for overview, execution scenarios, script
   relationships, gates, coverage, source landmarks, and synthesis views.
   The top badge tells you whether this is only a preflight map or a completed
   analysis view.
7. Read `report.md` or `report.html`, including the required action list, then
   check `source.json`, `inventory.json`, `coverage.json`,
   `findings.json`, `evidence.json`, `dependencies.json`, `sensitive.json`,
   `gates.json`, `gate_decisions.json`, `slices.json`, `review.json`,
   `security.json`, `supported_surfaces.json`, `connection_graph.json`,
   `reachability_scenarios.json`, `architecture_map.json`,
   `relation_map.json`, `source_landmarks.json`, `visualization_index.json`,
   `analysis_plan.json`, `cross_unit_analysis.json`, `synthesis.json`, and
   `followup_plan.json` before approving any next action.
8. If you want Codex to analyze slices manually one at a time, follow
   `gpt_work_order.md`: claim a job, export the allowed content range, write one
   unit-analysis JSON/JSONL result, complete the job, and repeat until no
   runnable jobs remain. Then run `git-scv continue <run-dir>` to generate
   `final_user_report.md/html`.
9. If you use bulk manual-export instead, `analysis import` marks only jobs
   whose `allowed_paths` match imported units as complete. Final report
   generation remains blocked until all runnable jobs are completed.
10. Treat `secret-candidate` findings as unresolved review items, not as safe or
   ignored files.
11. When using case packages, run `git-scv case verify-source <case-id>` before
   any install/build/test/run approval request.
12. Use `git-scv case next-action <case-id> --action install --argv <program>
   <arg>` to check source, manifest, receipt, and gate blockers before asking
   for execution approval.
13. Ask for explicit approval before running install, build, test, script, hook,
   binary, workflow, package-manager, or container commands from the inspected
   repository.
13. For agent-supplied unit analyses, run `git-scv validate-unit <run-dir>
   unit-analysis/U0001.json` or `git-scv validate-units <run-dir>` before
   treating unit claims as part of the case package. These validators check
   schema shape, evidence refs, and path boundaries; they do not prove semantic
   truth or malware absence.

## Sensitive Candidates

Git-SCV treats files such as `.env`, private-key names, certificates, and names
containing `secret` or `credential` as sensitive candidates. The default
inspection reports those paths without reading or copying their contents.

Sensitive candidates are not ignored and are not treated as safe. They are
reported as unresolved review items, especially when a repository might hide an
executable script behind a sensitive-looking name.

Optional sensitive-candidate review modes are explicit:

- `--sensitive-mode redacted-summary` with `--approve-sensitive-review` and
  `--sensitive-review-ack review-sensitive-candidates` records only path, size,
  and name-based metadata.
- `--sensitive-mode approved-raw` with `--approve-sensitive-review`,
  `--sensitive-review-ack review-sensitive-candidates`,
  `--approve-sensitive-raw`,
  `--sensitive-raw-ack include-approved-sensitive-raw-in-diagnostic-input`, and
  `--sensitive-path <repo-relative-path>` reads only listed paths that were
  detected as sensitive candidates, records static signal labels including
  common shell, Node, Python, PowerShell, and Ruby execution tokens, rejects
  URL-like path values, and still never stores raw sensitive contents in
  artifacts.

## Cleanup And Uninstall

Git-SCV writes artifacts only to the output directories you choose with `--out`.
Prefer managed case packages when cleanup safety matters.

Managed case packages can be removed with:

```sh
git-scv case delete <case-id> --ack delete-git-scv-case
git-scv case prune --all --ack delete-all-git-scv-cases
```

If you use the Hermes harness script, it creates per-case packages under
`${TMPDIR:-/tmp}/git-scv-cases` by default:

```sh
scripts/git-scv-hermes.sh cleanup <case-id> --ack delete-git-scv-case
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

Uninstall the binary installed by Cargo:

```sh
cargo uninstall git-scv
```

Git-SCV does not create background services, shell hooks, git hooks, or global
configuration.

## Status

v0.3.3 uses the schema-breaking artifact-contract-v2 release line. v0.2 artifacts are
not migrated; re-run inspection. Git-SCV does not claim repositories are safe,
clean, trusted, secure, safe-to-install, or safe-to-run.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
