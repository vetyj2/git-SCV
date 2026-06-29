# Git-SCV Usage Guide

This guide explains how to use Git-SCV to inspect an unfamiliar local
repository before installing, building, testing, or running it.

Git-SCV is a no-exec inspection tool. It reports observed files, evidence,
findings, skipped areas, and limits. It does not prove that a repository is
safe.

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

## Recommended Review Flow

1. Run `git-scv inspect <repo-path> --out <run-dir>`.
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
11. Use `review.json` for machine-readable totals, verdict, and required
   actions.
12. Use `security.json` as a first-pass machine-readable security summary for
   other tools. It references the source artifacts and is not a safety
   guarantee.
13. Use `connection_graph.json` and `analysis_plan.json` to see user-action to
   execution/model-input/sensitive-surface reachability and the planned unit
   and cross-unit review tasks.
14. Use `cross_unit_analysis.json`, `synthesis.json`, and `followup_plan.json`
   to see static aggregate scenarios, whole-repo diagnosis limits, and the
   next follow-up tasks. These artifacts still do not claim install or
   execution safety.
15. Treat `secret-candidate` findings as unresolved review items.
16. Ask for explicit approval before running any install, build, test, script,
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
  scripts/git-scv-hermes.sh inspect <repo-path> [label]

Inspect a verified HTTPS archive:
  scripts/git-scv-hermes.sh snapshot <archive-url> <sha256> [label]

Print the mandatory agent briefing:
  scripts/git-scv-hermes.sh brief <case-dir>

Delete one report package after review:
  scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case

Delete all local report packages:
  scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases

Uninstall Git-SCV:
  scripts/git-scv-hermes.sh uninstall
```

The legacy harness creates a per-repository package under
`${TMPDIR:-/tmp}/git-scv-cases` by default. The Rust case CLI creates managed
case packages under the configured Git-SCV case root.

The script only orchestrates Git-SCV and cleanup. It does not call a model and
does not make safety decisions. `inspect` and `snapshot` automatically print the
compact `git-scv brief` output after creating a case package. Agents must be
able to restate that brief before deciding what may be sent to a model or before
asking the user to approve execution. If the brief cannot be produced, stop and
run `scripts/git-scv-hermes.sh brief <case-dir>` again.

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
slices.json
review.json
security.json
connection_graph.json
analysis_plan.json
cross_unit_analysis.json
synthesis.json
followup_plan.json
agent_receipt.json (after `git-scv receipt create`)
report.md
report.html
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
13. `slices.json`: path-only reading slices derived from `sectors.json` and
   `gates.json`; each file may include a path or extension based language hint
   and deep-analysis candidate flag. Sensitive and execution candidates are
   excluded from default model input until separately approved.
14. `review.json`: machine-readable verdict, totals including deep-analysis
   candidate count, required actions, and structured approval acknowledgements.
15. `security.json`: machine-readable security summary for other tools. It
   mirrors verdict, counts, required actions, excluded paths, limitations, and
   source artifact references without reading new files or proving safety.
16. `connection_graph.json`: file, manifest, script, hook, workflow,
   dependency, sensitive candidate, prompt-injection surface, and approval-gate
   graph.
17. `analysis_plan.json`: unit-analysis and cross-unit synthesis plan, including
   allowed path boundaries and required cross-unit questions.
18. `cross_unit_analysis.json`: static aggregate scenario analysis and
   synergy/follow-up markers such as sensitive-plus-execution overlap.
19. `synthesis.json`: whole-repo diagnosis summary. It keeps
   `safe_claim_made:false` and records what cannot be concluded.
20. `followup_plan.json`: concrete next-round tasks when gates, unsupported
   surfaces, unresolved edges, or follow-up questions remain.
21. `agent_receipt.json`: agent acknowledgement bound to manifest and source
   fingerprint, created after `git-scv receipt create`.
22. `report.md`: human-readable Markdown summary, including sensitive review
   ack status and the required action list.
23. `report.html`: browser-friendly human-readable summary, including
   sensitive review ack status and required ack strings.

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

Artifacts are evidence packages. Git-SCV does not delete them automatically.
After the user has reviewed the report and decided what to do next, remove the
whole output package:

```sh
rm -rf <run-dir>
rm -rf <snapshot-dir>
```

When using `scripts/git-scv-hermes.sh`, prefer:

```sh
scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

`cleanup <case-dir>` refuses to delete paths outside the configured case root
and requires a harness sentinel plus the exact acknowledgement string.

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
