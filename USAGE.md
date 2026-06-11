# Git-SCV Usage Guide

This guide explains how to use Git-SCV to inspect an unfamiliar local
repository before installing, building, testing, or running it.

Git-SCV is a no-exec inspection tool. It reports observed files, evidence,
findings, skipped areas, and limits. It does not prove that a repository is
safe.

## Basic Command

```sh
git-scv inspect <repo-path> --out <run-dir>
```

Example:

```sh
git-scv inspect ./unknown-repo --out /tmp/git-scv-run
```

The output directory must be new or empty. Git-SCV refuses to write into a
non-empty output directory and refuses output paths inside the inspected
repository.

## Recommended Review Flow

1. Run `git-scv inspect <repo-path> --out <run-dir>`.
2. Open `<run-dir>/report.md` and read the summary first.
3. Open `coverage.json` to understand what was listed, read, skipped, or left
   unknown.
4. Open `findings.json` and follow each evidence ID into `evidence.json`.
5. Treat `secret-candidate` findings as unresolved review items.
6. Ask for explicit approval before running any install, build, test, script,
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
sectors.json
report.md
```

Use them in this order:

1. `run.json`: status, exit code, tool version, and stage outcomes.
2. `source.json`: inspected path and local git metadata, if present.
3. `coverage.json`: what Git-SCV read and what it skipped.
4. `findings.json`: review items and limitations.
5. `evidence.json`: evidence records referenced by findings.
6. `sectors.json`: suggested reading plan for deeper manual review.
7. `report.md`: human-readable summary.

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
inspection and should require explicit, path-specific user approval.

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
- fetch from remotes
- prove that a repository is safe

Use Git-SCV as the first review step, then decide what to inspect or approve
next.
