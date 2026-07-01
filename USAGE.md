# Git-SCV Usage Guide

This guide explains how to use Git-SCV to inspect an unfamiliar local
repository before installing, building, testing, or running it.

Git-SCV is a no-exec inspection tool. It reports observed files, evidence,
findings, skipped areas, and limits. It does not prove that a repository is
safe.

There are two layers:

- Git-SCV core preflight: `inspect`, `snapshot`, `github plan`, source binding,
  redaction, gates, slices, and static maps.
- Git-SCV orchestrator: `review`, `continue`, `sub_slices.jsonl`,
  `analysis_inputs.jsonl`, `analysis_jobs.jsonl`, `analysis job claim`,
  `analysis export-content`, `analysis job complete`, `analyze --backend
  manual-export`, `analysis import`, `watch`, `resume`, `gpt_work_order.json`,
  analysis map, and final user report generation.
- Git-SCV one-touch worker runtime: `scan --worker codex|claude|fake`
  orchestrates the same source-bound job queue through a configured external
  worker CLI, validates each unit-analysis result, and then generates the final
  user report when the queue is complete.

Preflight artifacts are not completed semantic repository analysis. The stage
is exposed as `analysis_stage` in brief, report, architecture, and analysis
runtime artifacts.

## Recommended Public Flow

For the normal "can I install/build/test/run this unfamiliar repo?" workflow,
start with the short public flow:

```sh
git-scv init
git-scv doctor
git-scv <repo-path-or-github-url>
```

`git-scv init` is the first-run setup check. It is Codex-first by default, but
it does not read Codex, Claude, OAuth, API, connector, or token files. It
checks worker readiness only through the configured worker CLI exit status and
redacted output, reminds the user that API-key based worker setups may incur
paid usage, and asks the user to verify the worker CLI model and
thinking/reasoning level before full screening.

`git-scv doctor` is the pre-work readiness check. It reports built-in
Codex/Claude linkage, the short command entrypoint, the adapter template path,
the auth-file boundary, likely remediation steps, and the next safe command.

`git-scv <repo-path-or-github-url>` opens the quick-start flow. In non-TTY
automation it avoids paid worker/API cost. For local paths it starts the
`local-preflight` path and stops at `pending-unit-analysis` until the user
explicitly starts worker analysis. For GitHub URLs it starts
`web-metadata-preflight`, which reads GitHub tree metadata only and clearly
reports `code_body_analysis=false`, `worker_started=false`, and
`semantic_analysis_complete=false`.

In an interactive terminal, a GitHub URL asks the user to choose:

1. web metadata preflight
2. pinned snapshot source analysis
3. local folder / already acquired source analysis

Use Up/Down or `j`/`k` to move through the few choices, Enter to confirm, or
`1`-`3` to choose directly. If Git-SCV cannot enter raw terminal selection, it
falls back to the same numbered prompt. Captured/non-TTY runs keep the safe
default and do not silently download source or start a worker.

The strict checksum path is deliberately separate: `strict-verified-snapshot`
requires a user-supplied SHA-256 digest from an external channel. The practical
GitHub convenience path is `pinned-snapshot`: Git-SCV resolves a ref to a commit
SHA, downloads that commit archive, records a self-observed SHA-256, and labels
the result `verification_level=pinned-commit-self-observed`. This is
reproducibility metadata, not independent external digest verification.

The explicit equivalents remain available:

```sh
git-scv scan <repo-path> --goal install --worker codex
git-scv scan <repo-path> --goal install --worker manual
git-scv scan https://github.com/<owner>/<repo> --mode web-metadata-preflight
git-scv scan https://github.com/<owner>/<repo> --mode pinned-snapshot --worker codex
git-scv review <repo-path> --goal install
git-scv review https://github.com/<owner>/<repo> --goal install
git-scv continue <run-dir>
```

`scan` is the one-touch path. With `--worker codex` or `--worker claude`, it
first runs preflight, then claims one source-bound job at a time, exports only
that job's redacted allowed content range, invokes the configured worker CLI,
validates the returned unit-analysis JSON/JSONL, repairs one formatting/schema
error by default with `--retry-format-errors 1`, completes the job, and repeats
until no runnable jobs remain. With `--worker manual`, it stops after writing
the same preflight/work-order/job artifacts.

Worker pacing controls are available for real CLI backends:

```sh
git-scv scan <repo-path> --worker codex --worker-delay-ms 1000
git-scv scan <repo-path> --worker codex --max-worker-calls-per-minute 10
git-scv scan <repo-path> --worker codex --max-jobs 5 --resume
git-scv scan <repo-path> --worker codex --stop-on-worker-error
```

Every worker attempt writes a non-empty `codex_invocation_receipt.jsonl` record
with redacted argv, prompt hash, schema hash, status, duration, retry count,
source fingerprint hash, artifact manifest hash, and explicit
`oauth_token_read:false`, `oauth_token_stored:false`, `raw_stdout_stored:false`,
and `raw_stderr_stored:false`.

`review` creates the no-exec preflight artifacts, source-bound work order,
analysis job queue, terminal progress panel, and `architecture.html` for agents
that want to claim/export/complete jobs explicitly. `continue` resumes the run
and generates `final_user_report.md/html` only after all runnable analysis jobs
are completed.

For GitHub URLs, `review` performs metadata-only planning through the GitHub
tree API. It does not fetch file bodies or create slice-analysis jobs. It stops
with `analysis_stage=web-metadata-preflight` and tells the user to use
`pinned-snapshot` or another local source acquisition path before full
slice-by-slice worker analysis.

Codex or another active agent session processes jobs with internal plumbing
commands:

```sh
git-scv analysis job list <run-dir>
git-scv analysis job claim <run-dir> --agent Codex
git-scv analysis export-content <run-dir> --job <job-id>
git-scv analysis job complete <run-dir> --job <job-id> --result <unit.jsonl>
git-scv analysis job fail <run-dir> --job <job-id> --reason <code>
```

These commands never run target repository code. Before claiming, exporting, or
completing a job, Git-SCV verifies the work-order binding and current source
fingerprint. If the source changed after review, the job flow stops with
`source-fingerprint-mismatch`; re-run `git-scv review`.

`analysis export-content` reads only the claimed job's allowed repo-relative
range, applies redaction, writes `analysis/content-export/<job-id>.json`, and
keeps `raw_content_stored:false`. OAuth/API/connector credentials are never
requested, stored, forwarded, serialized, or written into receipts.

Worker CLI auth policy:

- Git-SCV must not stat, list, read, hash, delete, write, or serialize Codex,
  Claude, OAuth, API, connector, or token files.
- Git-SCV recommends an already logged-in OAuth/subscription CLI session over
  storing API keys in project files. If the worker CLI is configured with API
  keys, full screening may consume paid API quota.
- Git-SCV uses the model and thinking/reasoning level configured in the worker
  CLI. Check those settings before `scan --worker codex|claude`.
- `git-scv worker doctor --backend codex` and `git-scv worker doctor --backend
  claude` check only allowlisted CLI command exit status plus redacted
  stdout/stderr.
- If worker auth is missing, Git-SCV tells the user to log in with the worker
  CLI outside the repository. It does not run login/logout flows and does not
  inspect auth storage.
- The worker executable must not live inside the target repository.

## Local Inspection

```sh
git-scv inspect <repo-path> --out <run-dir>
```

`<repo-path>` must be a local directory. Repository URL inputs such as
`https://...`, `git@host:owner/repo.git`, or `file://...` are rejected by
`inspect`. Download or clone the repository first, then inspect that local
directory.

Example:

```sh
git-scv inspect ./unknown-repo --out /tmp/git-scv-run
```

The output directory must be new or empty. Git-SCV refuses to write into a
non-empty output directory and refuses output paths inside the inspected
repository.

`source.json` may include git remote URLs from the local repository. Git-SCV
redacts URL user information, including token-like userinfo, before writing
those URLs to artifacts.

## Snapshot Inspection

Use `snapshot` when you have an HTTPS archive URL and a SHA-256 digest verified
through a separate channel.

```sh
git-scv snapshot <archive-url> --out <snapshot-dir> --sha256 <hex>
```

The `inspect` command never fetches from a remote. The separate `snapshot`
command downloads an HTTPS archive in memory, checks it against the
user-provided SHA-256 digest, and extracts only safe `.zip`, `.tar.gz`, or
`.tgz` entries into `<snapshot-dir>/source`, then writes the normal inspection
artifacts to `<snapshot-dir>/run`. It refuses requests without `--sha256`,
requires a 64-character hex SHA-256 digest, accepts only `https://` archive
URLs, rejects URL user information, and requires its output directory to be new
or empty. URL validation errors redact user information and query or fragment
details.

For successful snapshot runs, `run/source.json` records sanitized snapshot
metadata: the archive URL without query or fragment details, the verified
SHA-256 digest, archive format, and extracted source path.

## GitHub Remote Plan

Use `github plan` to read GitHub tree metadata before clone or archive
download:

```sh
git-scv github plan https://github.com/<owner>/<repo> --ref <sha-or-tag> --out <plan-dir>
```

This command does not clone the repository, download an archive, fetch file
bodies, or execute target content. It writes `github_remote_plan.json` with
tree entry counts, name-detected surfaces, truncation status, moving-ref
warning, and a remote fingerprint. Branch names are treated as moving refs
unless pinned by commit SHA.

## Orchestrator Flow

After `inspect`, Git-SCV writes LLM-oriented preparation artifacts:

```text
static_preflight_summary.json
sub_slices.json
sub_slices.jsonl
analysis_inputs.json
analysis_inputs.jsonl
analysis_state.json
analysis_events.jsonl
llm_backend.json
source_acquisition.json
gpt_work_order.json
gpt_work_order.md
work_order_binding.json
analysis_jobs.jsonl
codex_invocation_receipt.jsonl
analysis_map.json
analysis_followup_jobs.jsonl
```

Run manual export:

```sh
git-scv analyze <run-dir> --backend manual-export
git-scv watch <run-dir>
```

The manual backend writes prompt/input bundles under
`<run-dir>/analysis/manual-export/`. It does not call a model. The exported
bundles reference safe, gate-aware input metadata and do not embed target file
raw bodies.

If no automated LLM CLI backend is available, use `gpt_work_order.json` or
`gpt_work_order.md` as the handoff receipt. It records the exact ordered steps,
stop conditions, required input artifacts, expected output artifacts, and the
handoff prompt GPT should follow. The manual-export directory also receives
`GPT_WORK_ORDER.md` so a GPT session that is given only the exported bundles
still knows to process them in order and to stop at gates.

Codex OAuth or other agent credentials are outside the Git-SCV artifact
contract. They may be held temporarily by the user's terminal or active Codex
session, but Git-SCV must not request, read, store, forward, or serialize those
tokens. Do not put OAuth tokens, API keys, or connector credentials in the
repository, run directory, work order, unit-analysis files, stdout, or stderr.

Job-based analysis is the preferred runtime path because it keeps source,
work-order, and Codex receipts tied to each slice. Bulk manual export remains
available:

```sh
git-scv analysis import <run-dir> <unit-results.jsonl>
git-scv resume <run-dir>
git-scv report final <run-dir>
```

`analysis import` validates each unit-analysis record against the run's
evidence IDs, path boundaries, and raw marker scan before appending
`unit_analysis.jsonl`. It marks only matching queued/claimed jobs complete.
`report final` is blocked while runnable jobs remain queued, claimed, or
failed, and until `analysis_map.json` is complete.

## One-Touch Worker Runtime

Use `scan` when the user wants one command to drive slice analysis:

```sh
git-scv init
git-scv doctor
git-scv ./unknown-repo
git-scv worker doctor --backend codex
git-scv scan ./unknown-repo --goal install --worker codex
```

Useful variants:

```sh
git-scv scan ./unknown-repo --goal install --worker claude
git-scv scan ./unknown-repo --goal install --worker manual
git-scv scan ./unknown-repo --goal install --worker codex --progress plain
git-scv scan ./unknown-repo --goal install --worker codex --progress jsonl
```

`--progress auto` treats the terminal as a compact status dashboard: when
stdout is a terminal it redraws a short one-line status with stage, percent,
current job/path, and next safe command. Captured output falls back to stable
plain key-value progress. Git-SCV does not clear scrollback or use the
alternate screen by default. Use `--progress plain` for logs, `--progress
jsonl` for automation, and `--progress quiet` for wrappers that render their
own dashboard.

Terminal output is intentionally terse. It tells the user what is happening,
whether the run is waiting/blocked/failed/complete, and which command or
artifact to open next. Detailed evidence, slice reasoning, source maps, and
repo explanations belong in `brief.md`, `final_user_report.md`, and
`architecture.html`.

Default real worker commands are shell-free and intentionally small:

- Codex: `codex exec --ephemeral --skip-git-repo-check --color never -`
- Claude: `claude -p`

Set `GIT_SCV_CODEX_BIN`, `GIT_SCV_CODEX_WORKER_ARGS`,
`GIT_SCV_CLAUDE_BIN`, or `GIT_SCV_CLAUDE_WORKER_ARGS` if your local CLI uses a
different non-shell invocation. These variables configure worker CLI behavior
only; they are not token variables and must not contain secrets.

For other coding-agent CLIs, copy
`scripts/git-scv-worker-adapter.example.py` outside the target repository and
customize only non-secret command/argument values. Do not put OAuth tokens, API
keys, or connector credentials into the adapter, environment overrides, run
directory, or target repository.

## Recommended Review Flow

1. Run `git-scv review <repo-path> --goal install`.
2. Run `git-scv brief <run-dir>` and summarize `verdict`, `action_required`,
   required action ids, default model excluded path count,
   `artifact_manifest_sha256`, `source_fingerprint_hash`, and
   `agent_read_receipt` before any next action.
3. If an agent is continuing, create a receipt:
   `git-scv receipt create <run-dir> --agent Hermes --summary-file <summary.md>
   --summarized-to-user --blocked-actions-acknowledged`.
4. Open `<run-dir>/report.md` and read the summary, including sensitive
   review ack status and the required action list.
5. Open `coverage.json` to understand what was listed, read, skipped, or left
   unknown.
6. Open `findings.json` and follow each evidence ID into `evidence.json`.
7. Open `sensitive.json` and confirm whether sensitive candidates were excluded,
   summarized, or path-approved for raw review, including approval and ack
   confirmation state.
8. Open `dependencies.json` to review direct dependency names and source kinds.
   Git-SCV does not store raw version ranges, URLs, git addresses, or local
   paths there.
9. Open `gates.json` before model input or any install, build, test, script,
   hook, binary, or container approval request. Execution candidates also
   require approval before model input.
10. Use `slices.json` as the path-only reading plan for later model input.
   Sensitive, automatic-execution, and execution-related candidates are excluded
   from default model input until separately approved.
11. Use `gpt_work_order.md`, `sub_slices.jsonl`, `analysis_inputs.jsonl`, and
   `analysis_jobs.jsonl` when actual LLM unit analysis is needed. Codex should
   claim one job, export one allowed content range, write one unit-analysis
   result, and complete that job before moving to the next.
12. Use `analysis_state.json` and `git-scv watch <run-dir>` to tell whether the
   run is only planned, blocked, in progress, imported, or ready for final
   report generation.
13. Use `review.json` for machine-readable totals, verdict, and required
   actions.
14. Use `security.json` as a first-pass machine-readable security summary for
   other tools. It references the source artifacts and is not a safety
   guarantee.
15. Use `connection_graph.json` and `analysis_plan.json` to see user-action to
   execution/model-input/sensitive-surface reachability and the planned unit
   and cross-unit review tasks.
16. Use `cross_unit_analysis.json`, `synthesis.json`, and `followup_plan.json`
   to see static aggregate scenarios and follow-up tasks. Unless
   `analysis_stage` says meta-synthesis is complete, these artifacts are not a
   completed semantic repository report.
17. Treat `secret-candidate` findings as unresolved review items.
18. Ask for explicit approval before running any install, build, test, script,
   hook, binary, or container command from the inspected repository.

## Case Packages

Use cases when an agent needs a stable package that can be checked again before
execution approval:

```sh
git-scv case create <repo-path>
git-scv case list
git-scv case show <case-id>
git-scv case brief <case-id>
git-scv case verify-source <case-id>
git-scv case status <case-id>
git-scv case delete <case-id> --ack delete-git-scv-case
git-scv case prune --all --ack delete-all-git-scv-cases
git-scv case doctor
```

If `verify-source` reports `stale-source`, prior reports, receipts, and gate
decisions must be treated as stale.

## Hermes Harness

Hermes-style agents can call Git-SCV directly or use the optional repository
script:

```sh
scripts/git-scv-hermes.sh commands
```

Common mappings:

```text
Install Git-SCV:
  scripts/git-scv-hermes.sh install

Update Git-SCV from the GitHub repository:
  scripts/git-scv-hermes.sh update-latest

Inspect a local repository:
  scripts/git-scv-hermes.sh inspect <repo-path>

Inspect a verified HTTPS archive:
  scripts/git-scv-hermes.sh snapshot <archive-url> <sha256> [label]

Print the mandatory agent briefing:
  scripts/git-scv-hermes.sh brief <case-id>

Check whether a next action is blocked:
  scripts/git-scv-hermes.sh next-action <case-id> --action install --argv <program> <arg>

Delete one report package after review:
  scripts/git-scv-hermes.sh cleanup <case-id> --ack delete-git-scv-case

Delete all local report packages:
  scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases

Uninstall Git-SCV:
  scripts/git-scv-hermes.sh uninstall
```

The harness delegates local inspect, brief, next-action, list, and cleanup to
the Rust case CLI. Case packages are stored under the configured Git-SCV case
root.

The script only orchestrates Git-SCV case commands and cleanup. It does not call
a model and does not make safety decisions. `inspect` automatically prints the
compact `git-scv case brief` output after creating a case package. Agents must
be able to restate that brief before deciding what may be sent to a model or
before asking the user to approve execution. If the brief cannot be produced,
stop and run `scripts/git-scv-hermes.sh brief <case-id>` again.

## Artifact Files

Git-SCV writes these files:

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
gpt_work_order.json
gpt_work_order.md
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
analysis_followup_jobs.jsonl
cross_unit_analysis.json
synthesis.json
followup_plan.json
agent_receipt.json (after `git-scv receipt create`)
report.md
report.html
architecture.html
```

Use them in this order:

1. `brief.json` / `brief.md`: one-screen agent entrypoint with manifest and
   source fingerprint hashes.
2. `artifact_manifest.json`: artifact hash chain and artifact-contract-v2
   metadata.
3. `run.json`: status, exit code, tool version, and stage outcomes.
4. `source.json`: inspected path and local git metadata, if present. Remote URL
   user information is redacted.
5. `inventory.json`: listed files, skipped paths, symlink records, and path
   metadata.
6. `coverage.json`: what Git-SCV read and what it skipped.
7. `findings.json`: review items and limitations.
8. `evidence.json`: redacted evidence records referenced by findings.
9. `dependencies.json`: direct dependency names and source kinds from readable
   manifests; raw specs are not stored.
10. `sectors.json`: suggested reading plan for deeper manual review. Manifest,
   automatic-execution, entrypoint, and language deep-analysis candidates are
   ordered before the remaining size-sorted files.
11. `sensitive.json`: sensitive-candidate mode, approvals, ack confirmations,
   candidates, and redacted review signals.
12. `gates.json`: sensitive raw-review and execution approval candidate lists,
   including execution approval before model input and structured sensitive
   review ack strings.
13. `gate_decisions.json`: source/artifact-bound approval-decision envelope.
   No approval is created automatically.
14. `slices.json`: path-only reading slices derived from `sectors.json` and
   `gates.json`; each file may include a path or extension based language hint
   and deep-analysis candidate flag. Sensitive and execution candidates are
   excluded from default model input until separately approved.
15. `gpt_work_order.json` / `gpt_work_order.md`: GPT handoff receipt for the
   manual-export path. It lists ordered steps, stop conditions, required input
   artifacts, expected output artifacts, and the exact handoff prompt an agent
   should follow when no automated LLM CLI backend is available. It records
   `oauth_token_stored:false` and `oauth_token_forwarded:false`; credentials
   remain in the user's external terminal or Codex session.
16. `review.json`: machine-readable verdict, totals including deep-analysis
   candidate count, required actions, and structured approval acknowledgements.
17. `security.json`: machine-readable security summary for other tools. It
   mirrors verdict, counts, required actions, excluded paths, limitations, and
   source artifact references without reading new files or proving safety.
18. `supported_surfaces.json`: parsed, name-detected, unsupported, and
   parse-failed capability matrix.
19. `connection_graph.json`: file, manifest, script, hook, workflow,
   dependency, sensitive candidate, prompt-injection surface, and approval-gate
   graph.
20. `reachability_scenarios.json`: user-action to reachable-node scenarios.
21. `architecture_map.json`: repo shape, sectors, entrypoints, and architecture
   summary with `safe_claim_made:false`.
22. `relation_map.json`: script, scenario, manifest, config, dependency, and
   gate relations.
23. `source_landmarks.json`: recommended reading order, do-not-read-by-default,
   and gate-before-reading paths.
24. `visualization_index.json`: views and privacy contract for
   `architecture.html`.
25. `analysis_plan.json`: unit-analysis and cross-unit synthesis plan, including
   allowed path boundaries and required cross-unit questions.
26. `cross_unit_analysis.json`: static aggregate scenario analysis and
   synergy/follow-up markers such as sensitive-plus-execution overlap.
27. `synthesis.json`: whole-repo diagnosis summary. It keeps
   `safe_claim_made:false` and records what cannot be concluded.
28. `followup_plan.json`: concrete next-round tasks when gates, unsupported
   surfaces, unresolved edges, or follow-up questions remain.
29. `agent_receipt.json`: agent acknowledgement bound to manifest and source
   fingerprint, created after `git-scv receipt create`.
30. `report.md`: human-readable Markdown summary, including sensitive review
   ack status and the required action list.
31. `report.html`: browser-friendly human-readable summary, including
   sensitive review ack status and required ack strings.
32. `architecture.html`: default interactive local viewer for overview,
   execution scenarios, script relations, gates, coverage, landmarks, and
   synthesis. It does not execute target repo HTML or JavaScript.

## Unit Analysis Loop

Git-SCV can validate agent-produced unit-analysis JSON against the existing
case package:

```sh
git-scv validate-unit <run-dir> unit-analysis/U0001.json
git-scv validate-units <run-dir>
git-scv synthesize <run-dir>
git-scv followup-plan <run-dir>
git-scv validate-followup <run-dir>
```

`validate-unit` checks required fields, evidence references, repo-relative path
boundaries, forbidden paths, and raw-marker leakage. It cannot prove semantic
truth, malware absence, or install safety. `synthesize` and `followup-plan`
summarize the static artifacts already produced by inspection.

## Artifact Cleanup

Artifacts are evidence packages. Git-SCV does not delete ad hoc `--out`
directories automatically. Prefer managed case packages when cleanup safety
matters.

When using `scripts/git-scv-hermes.sh`, prefer:

```sh
scripts/git-scv-hermes.sh cleanup <case-id> --ack delete-git-scv-case
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

`cleanup <case-id>` delegates deletion to `git-scv case delete`, which refuses
paths outside the configured case root and requires the exact acknowledgement
string.

## Required Actions

`review.json.required_actions` is the machine-readable checklist to review
before handing files to a model or approving any install, build, test, script,
hook, binary, or container command.

- `sensitive-raw-review`: sensitive-candidate contents remain excluded unless
  the user gives both approval flags, both exact ack strings, and explicit
  repo-relative paths.
- `execution-model-input-review`: automatic-execution and execution-related
  paths require human approval before those paths are used as model input.
- `execution-command-review`: install/build/test/run approvals require an exact
  command envelope bound to the current source fingerprint and artifact
  manifest.
- `oversized-slice-review`: one or more path-only reading slices exceeds the
  token planning budget. This is a model-input planning warning, not a safety
  verdict. Split, summarize, or inspect those paths separately before sending
  them to a model.

## Sensitive Candidates

Git-SCV treats files such as `.env`, private-key names, certificate extensions,
and names containing `secret` or `credential` as sensitive candidates.

Default behavior:

- Report the path as a finding.
- Do not read or copy the file contents.
- Do not treat the file as safe.
- Do not ignore the file.

This matters because an unknown repository can hide executable content behind a
sensitive-looking filename. For example, a file such as `.env.sh` should remain
both a sensitive candidate and a shell-script review item.

Raw-content analysis of sensitive candidates must happen outside the default
inspection and requires explicit, path-specific approval.

Sensitive-candidate review modes:

```sh
git-scv inspect <repo-path> --out <run-dir>
```

Default mode. Sensitive candidates are listed but not read.

```sh
git-scv inspect <repo-path> --out <run-dir> \
  --sensitive-mode redacted-summary \
  --approve-sensitive-review \
  --sensitive-review-ack review-sensitive-candidates
```

Redacted summary mode. Git-SCV records path, size, and name-based metadata only.
It does not read candidate contents.

```sh
git-scv inspect <repo-path> --out <run-dir> \
  --sensitive-mode approved-raw \
  --approve-sensitive-review \
  --sensitive-review-ack review-sensitive-candidates \
  --approve-sensitive-raw \
  --sensitive-raw-ack include-approved-sensitive-raw-in-diagnostic-input \
  --sensitive-path <repo-relative-path>
```

Approved raw mode. Git-SCV reads only the listed candidate path or paths after
both approval flags and both exact ack strings are present. It records static
signal labels such as script markers or command-token presence including common
shell, Node, Python, PowerShell, and Ruby execution tokens. It does not store
raw candidate contents in artifacts.

Each `--sensitive-path` value must be a repository-relative path that Git-SCV
detected as a sensitive candidate in the same run. URL-like values such as
`file://...` are rejected. Other paths are rejected so a user cannot
accidentally believe a non-candidate file was reviewed by the sensitive
candidate gate.

## Interpreting Findings

Findings are review prompts, not verdicts.

- `auto-exec-hook`: may run during install, build, editor open, directory entry,
  or git hook setup.
- `shell-script`: script file exists; Git-SCV does not prove whether it is
  called.
- `secret-candidate`: contents were not read; review is unresolved.
- `manifest`: context file such as `package.json`, lockfiles, or Cargo files.

Always read the limitation text with each finding.

## Exit Codes

```text
0  success
2  user input error
3  inspection failure
4  artifact validation failure
```

## What Git-SCV Does Not Do

Git-SCV does not:

- install dependencies
- build the project
- run tests
- execute scripts
- run hooks
- run binaries
- build or run containers
- fetch from remotes during `inspect`
- prove that a repository is safe

Use Git-SCV as the first review step, then decide what to inspect or approve
next.
