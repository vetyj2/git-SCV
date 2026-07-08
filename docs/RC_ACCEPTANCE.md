# Git-SCV v0.3.4 RC Acceptance

The v0.3.4 release candidate is accepted only when the tagged GitHub install
flow, no-exec/no-leak contracts, source-bound analysis job workflow, and final
report blocking behavior all match the CLI and generated artifacts.

## A. New-User Local Inspect Flow

- Install with a tag or reviewed revision.
- Run `git-scv init` once and confirm it prints the Codex-first recommendation,
  OAuth/token non-access policy, API-key paid-usage warning, model/thinking
  level reminder, worker readiness, and the next safe command:
  `git-scv <repo-path-or-github-url>`.
- Run `git-scv doctor` and confirm it reports the short entry command,
  built-in Codex/Claude/fake/manual linkage, adapter template path, auth-file
  boundary, readiness state, likely remediation lines, and `doctor_ready`.
- Run `git-scv <repo-path>` in a non-interactive context and confirm it
  defaults to `quick_flow=local-preflight`, uses manual worker mode, avoids
  paid worker invocation, reports `worker_started=false`, and leaves the run at
  `pending-unit-analysis`.
- Run `git-scv <repo-path-or-github-url>` in an interactive terminal and
  confirm the quick-start menu moves with Up/Down and `j`/`k`, confirms with
  Enter, still accepts `1`-`3`, and falls back to the numbered prompt if raw
  terminal selection is unavailable.
- Run `git-scv worker doctor --backend codex` on a machine with Codex CLI, or
  `git-scv worker doctor --backend fake` with a test worker.
- Run `git-scv scan <repo-path> --goal install --worker fake` in CI and confirm
  the run reaches `final_user_report.md/html` without executing target repo
  content.
- Run `git-scv review <repo-path> --goal install` for the recommended
  slice-review workflow.
- Confirm terminal progress works as a compact dashboard: TTY output stays
  short and redraw-safe, captured output remains plain key-value, and both show
  `analysis_stage`, dashboard status, source status, gate status,
  completed/queued/claimed/failed/blocked job counts, final report readiness,
  `target_repo_commands_executed=false`, and the next safe command.
- Confirm terminal output does not dump evidence bodies, slice contents, raw
  worker output, or long report prose; those details must stay in artifacts and
  HTML/Markdown reports.
- Confirm `work_order_binding.json`, `analysis_jobs.jsonl`, `gpt_work_order.md`,
  `brief.md`, and `architecture.html` exist.
- A Codex/Hermes session can claim one job, export one allowed content range,
  write one unit-analysis JSON/JSONL result, complete that job, and repeat.
- `git-scv scan <repo-path> --goal install --worker codex` must process queued
  jobs sequentially through the allowlisted worker CLI boundary when the user's
  terminal already has a working Codex CLI session.
- If a worker returns malformed unit-analysis JSON, Git-SCV must write a
  `schema-invalid` receipt, retry within `--retry-format-errors`, and either
  complete with a `schema-valid` receipt or leave the final report blocked with
  a non-empty failure receipt.
- `analysis_map.json` and `final_user_report.md/html` must include validated
  qualitative digests, scoped uncertainty, relation candidates, and queued
  follow-up jobs when workers provide them.
- `git-scv continue <run-dir>` must not create `final_user_report.md/html`
  while runnable jobs are queued, claimed, or failed.
- After all runnable jobs are completed, `git-scv continue <run-dir>` writes
  `final_user_report.md` and `final_user_report.html`.
- Run `git-scv case create <repo-path>`.
- Run `git-scv case brief <case-id>`.
- Open `architecture.html` from the case package.
- Confirm brief verdict, action_required, blocked actions, required approvals,
  source fingerprint hash, and artifact manifest hash.
- Run `git-scv case verify-source <case-id>` before any install/build/test/run
  approval request.
- Use `git-scv case next-action <case-id> --action install --argv <program>
  <arg>` to confirm the next action is blocked or allowed.
- Delete with `git-scv case delete <case-id> --ack delete-git-scv-case`.

## B. Snapshot Flow

- Use only an HTTPS archive URL plus a SHA-256 digest obtained through a
  separate channel.
- Run `git-scv snapshot <url> --out <snapshot-dir> --sha256 <sha256>`.
- Digest mismatch or archive failure must not echo raw URL query, fragment,
  userinfo, or token-like markers.
- Inspect the generated `run/brief.md`, `run/report.md`, and
  `run/architecture.html`.
- Confirm source fingerprint and artifact manifest exist.

## B2. GitHub Metadata Plan Flow

- Run `git-scv https://github.com/<owner>/<repo>` and confirm the guided quick
  flow does not start a worker until source acquisition has been completed.
- Run `git-scv review https://github.com/<owner>/<repo> --goal install` or
  `git-scv github plan ...`.
- Git-SCV must not clone, download archives, fetch file bodies, or execute
  target content.
- Output must clearly say `analysis_stage=web-metadata-preflight` or
  `source_acquisition=web-metadata-preflight`, with
  `code_body_analysis=false`, `worker_started=false`, and
  `semantic_analysis_complete=false`.
- Output must tell the user to use `pinned-snapshot` or another local source
  acquisition path before full slice review.
- The metadata plan must not be presented as completed semantic repository
  analysis.

## B3. GitHub Pinned Snapshot Flow

- Run `git-scv scan https://github.com/<owner>/<repo> --mode pinned-snapshot
  --worker manual` or the equivalent fake-worker test fixture.
- Git-SCV must resolve the requested ref to a commit SHA, download that commit
  archive, safely extract it, and then continue into the normal local scan/job
  queue path.
- `source.json` or `source_acquisition.json` must record
  `external_digest_verified=false`,
  `self_observed_digest_recorded=true`, and
  `verification_level=pinned-commit-self-observed`.
- This flow must not be described as strict checksum verification.

## C. Agent Flow

Hermes or another agent must be able to handle:

- "Set up Git-SCV first."
- "Check whether Codex/Claude linkage is ready."
- "Inspect this repo with Git-SCV first."
- "Review this repo slice by slice before I install it."
- "Summarize only the brief."
- "Show current Git-SCV progress."
- "Continue the Git-SCV review."
- "Explain the repo structure from architecture.html."
- "Tell me whether install is currently blocked and why."
- "Show execution candidates before model-input approval."
- "Delete this case."
- "Prune all Git-SCV cases."
- "Update or uninstall Git-SCV."

The agent must summarize the brief before requesting model-input approval or
execution approval. It must create an agent receipt before a blocked next
action can proceed.

Before starting real Codex/Claude worker analysis, the agent must show the
`git-scv init` or `git-scv doctor` readiness result, warn that API-key based
worker configuration may incur paid usage, and ask the user to confirm the
worker CLI model and thinking/reasoning level.

For the job runtime, the agent must use `analysis job claim`,
`analysis export-content`, and `analysis job complete` rather than browsing
arbitrary repo files by hand. Claim/export/complete must fail on stale source.
`codex_invocation_receipt.jsonl` must record `oauth_token_stored:false`,
`oauth_token_forwarded:false`, and `target_repo_commands_executed:false`.

## D. No-Leak Flow

The RC fails if any artifact, stdout, stderr, report, or HTML contains raw:

- URL query, fragment, or userinfo.
- Token-like or bearer-like marker.
- Raw lifecycle command containing a secret-like marker.
- Raw sensitive content.
- Raw command-line arguments.
- Raw target HTML/script injection payload.
- OAuth/API/connector credentials.

## E. No-Exec Flow

The RC fails if Git-SCV or its wrapper executes target repo install, build,
test, script, hook, binary, workflow, package-manager, or container commands.
The only process-spawning exception is an allowlisted worker CLI executable
outside the target repository. A worker executable inside the target repository
is an RC failure.

## E2. Worker Auth Boundary

The RC fails if Git-SCV stats, lists, reads, hashes, deletes, writes, or
serializes Codex/Claude/OAuth/API/token files or auth directories. Worker
readiness may be inferred only from allowlisted worker CLI exit status and
redacted stdout/stderr.

The adapter template must remain a non-secret example. It may contain command
shape examples, but must not contain deploy keys, OAuth tokens, API keys,
connector credentials, private URLs, or user-specific auth paths.

## F. Stale-Source Flow

After inspection, changing the source must make:

- `git-scv case verify-source <case-id>` fail.
- `git-scv analysis job claim <run-dir> --agent Codex` fail for review runs
  with a local runtime pointer.
- `git-scv analysis export-content <run-dir> --job <job-id>` fail if the source
  changed after the job was claimed.
- Prior gate decisions and receipts stale for execution purposes.
- `git-scv case next-action <case-id> --action install --argv <program> <arg>`
  return `allowed:false` with `stale-source`.

## G. Actionability Flow

`brief.md`, `report.md`, `report.html`, and `architecture.html` must show:

- What is blocked.
- Why it is blocked.
- Which artifact to inspect next.
- Which exact ack/action is required for approval.
- Which actions must not be run yet.
- What Git-SCV did not prove.
- Which architecture.html view to inspect first.

## H. Visualization Flow

`architecture.html` must be generated by default and must expose:

- Overview map.
- Execution scenario reachability.
- Script relationship view.
- Dependency/package surface view or summary.
- Security gate overlay.
- Coverage and unknowns view.
- Source landmarks.
- Synthesis view.

It must not use external network, target repo JavaScript/HTML execution, `eval`,
`new Function`, or raw target values as executable HTML.
