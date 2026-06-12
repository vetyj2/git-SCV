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
2. Open `<run-dir>/report.md` and read the summary first, including sensitive
   review ack status.
3. Open `coverage.json` to understand what was listed, read, skipped, or left
   unknown.
4. Open `findings.json` and follow each evidence ID into `evidence.json`.
5. Open `sensitive.json` and confirm whether sensitive candidates were excluded,
   summarized, or path-approved for raw review, including approval and ack
   confirmation state.
6. Open `dependencies.json` to review direct dependency names and source kinds.
   Git-SCV does not store raw version ranges, URLs, git addresses, or local
   paths there.
7. Open `gates.json` before model input or any install, build, test, script,
   hook, binary, or container approval request. Execution candidates also
   require approval before model input.
8. Use `slices.json` as the path-only reading plan for later model input.
   Sensitive, automatic-execution, and execution-related candidates are excluded
   from default model input until separately approved.
9. Use `review.json` for machine-readable totals, verdict, and required
   actions.
10. Treat `secret-candidate` findings as unresolved review items.
11. Ask for explicit approval before running any install, build, test, script,
   hook, binary, or container command from the inspected repository.

## Artifact Files

Git-SCV writes these files:

```text
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
review.json
report.md
report.html
```

Use them in this order:

1. `run.json`: status, exit code, tool version, and stage outcomes.
2. `source.json`: inspected path and local git metadata, if present. Remote URL
   user information is redacted.
3. `coverage.json`: what Git-SCV read and what it skipped.
4. `findings.json`: review items and limitations.
5. `evidence.json`: evidence records referenced by findings.
6. `dependencies.json`: direct dependency names and source kinds from readable
   manifests; raw specs are not stored.
7. `sectors.json`: suggested reading plan for deeper manual review. Manifest,
   automatic-execution, entrypoint, and language deep-analysis candidates are
   ordered before the remaining size-sorted files.
8. `sensitive.json`: sensitive-candidate mode, approvals, ack confirmations,
   candidates, and redacted review signals.
9. `gates.json`: sensitive raw-review and execution approval candidate lists,
   including execution approval before model input and structured sensitive
   review ack strings.
10. `slices.json`: path-only reading slices derived from `sectors.json` and
   `gates.json`; each file may include a path or extension based language hint
   and deep-analysis candidate flag. Sensitive and execution candidates are
   excluded from default model input until separately approved.
11. `review.json`: machine-readable verdict, totals including deep-analysis
   candidate count, required actions, and structured approval acknowledgements.
12. `report.md`: human-readable Markdown summary, including sensitive review
   ack status.
13. `report.html`: browser-friendly human-readable summary, including
   sensitive review ack status and required ack strings.

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
