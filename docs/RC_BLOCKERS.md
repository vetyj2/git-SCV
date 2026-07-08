# Git-SCV v0.3.4 RC Blockers

Do not publish the release if any of these are true.

- README, Cargo.toml, tag, release notes, or install commands disagree on the
  version.
- A documented CLI command is missing.
- The documented artifact set does not match generated artifacts.
- `git-scv init` is missing, fails without a clear diagnostic, or omits the
  Codex-first recommendation, OAuth/token non-access policy, API-key cost
  warning, model/thinking-level reminder, worker readiness state, or next safe
  command.
- `git-scv doctor` is missing, fails without a clear diagnostic, or omits the
  short entry command, built-in Codex/Claude linkage, adapter template path,
  auth-file boundary, likely remediation lines, or readiness state.
- `git-scv <repo-path-or-github-url>` does not enter the quick flow, or its
  non-interactive default starts a paid worker instead of local preflight or
  web metadata preflight.
- The interactive quick-start menu cannot be navigated with Up/Down, confirmed
  with Enter, or selected directly with `1`-`3`, or it fails to fall back to the
  numbered prompt when raw terminal selection is unavailable.
- GitHub metadata-only output fails to report `code_body_analysis=false`,
  `worker_started=false`, and `semantic_analysis_complete=false`.
- GitHub metadata-only output is presented as completed semantic repository
  analysis.
- GitHub URL quick/scan flow starts Codex/Claude worker analysis before pinned
  source acquisition.
- A pinned GitHub snapshot records a self-observed archive hash as if it were
  independent external SHA-256 verification.
- `strict-verified-snapshot` does not require a user-supplied external digest.
- `git-scv review <repo-path> --goal install` cannot create a source-bound
  review run with `analysis_jobs.jsonl` and terminal progress.
- `git-scv scan <repo-path> --goal install --worker fake` cannot complete a
  source-bound fake-worker run through final_user_report.md/html in CI.
- The worker prompt, `schemas/unit_analysis.schema.json`, and
  `validate-unit` validator require different unit-analysis fields.
- A worker formatting/schema failure cannot be retried or leaves no actionable
  validation error.
- A worker attempt starts but `codex_invocation_receipt.jsonl` is empty or
  missing after process failure, schema failure, repair, or success.
- Final reports ignore worker qualitative digest, scoped uncertainty,
  relation candidates, or follow-up jobs when those fields are present in
  validated unit-analysis.
- `git-scv scan <repo-path> --goal install --worker codex` executes anything
  other than the configured Codex worker CLI process outside the target repo.
- A worker executable inside the target repository is accepted.
- Git-SCV stats, lists, reads, hashes, deletes, writes, or serializes
  Codex/Claude/OAuth/API/token files or auth directories.
- `scripts/git-scv-worker-adapter.example.py` contains OAuth tokens, API keys,
  connector credentials, deploy keys, private URLs, user-specific auth paths,
  or instructions to put secrets in environment overrides.
- `git-scv continue <run-dir>` creates a final user report while runnable jobs
  are still queued, claimed, or failed.
- `analysis job claim`, `analysis export-content`, or `analysis job complete`
  proceeds after the source fingerprint changed.
- `analysis export-content` exports a blocked job or a job that was not claimed.
- `analysis job complete` stores an absolute result-file path instead of a
  run-relative `analysis/job-results/...` ref.
- `codex_invocation_receipt.jsonl`, `work_order_binding.json`, stdout, stderr,
  or reports indicate OAuth/API tokens were stored or forwarded.
- Raw token, URL query, URL fragment, URL userinfo, secret-like marker, raw
  lifecycle command, raw sensitive content, or raw HTML injection appears in
  artifacts, stdout, stderr, report.md, report.html, or architecture.html.
- `run.json.command.raw_args_stored` is true.
- Command-like evidence has `raw_excerpt_stored:true` or stores a raw command
  body.
- The no-exec sentinel fixture is triggered.
- Source changes are not detected by `case verify-source`.
- `case next-action` allows install/build/test/run with stale source, missing
  receipt, missing exact command envelope, or unresolved execution gate.
- Cleanup can delete outside the configured case root or delete source paths.
- `brief.md` lacks verdict, action_required, blocked reasons, next safe
  commands, visual output path, or no-safe-claim language.
- Terminal dashboard output spams evidence bodies, slice contents, raw worker
  stdout/stderr, or long report prose instead of compact status and next-action
  hints.
- Captured progress output is not stable plain key-value or JSONL, or TTY
  progress clears scrollback/uses an alternate screen by default.
- Unsupported or parse-failed execution surface still allows
  `no-blocker-observed`.
- report.html or architecture.html contains raw injection payload or executes
  target repo HTML/JS.
- `case show` or `case status` leaks the absolute source path by default.
- `cargo fmt`, `cargo test`, `cargo clippy --all-targets`, schema validation,
  script syntax checks, secret scan, version consistency check, or fresh
  `cargo install --git ... --tag v0.3.4 --locked` test fail.
- `cargo package --locked` fails for a crates.io release path.

Non-blockers before stable:

- Complete parser support for every ecosystem.
- Full package-manager acquisition path expansion.
- Advanced graph layout and minimap.
- Optional shellcheck integration when unavailable locally.
- Hard CI performance budgets.
