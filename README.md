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

Then install Git-SCV from a local checkout:

```sh
cargo install --path .
```

## Build

```sh
cargo build
```

## Usage

```sh
git-scv inspect <repo-path> --out <run-dir>
```

`<repo-path>` must be a local directory. Repository URL inputs such as
`https://...`, `git@host:owner/repo.git`, and `file://...` are rejected until
the snapshot flow is implemented. Download or clone the repository first, then
inspect that local directory.

The `inspect` command never fetches from a remote. A future snapshot command
will be separate from `inspect` and is planned to use archive download plus a
user-provided checksum before handing a local snapshot to the inspector.

For the recommended review flow and artifact reading order, see
[USAGE.md](USAGE.md).

The output directory must be new or empty. Git-SCV does not execute install,
build, test, script, hook, binary, or container commands from the inspected
repository.

When Git-SCV records git remote URLs in `source.json`, URL user information is
redacted so access tokens are not copied into artifacts.

The run directory contains machine-readable artifacts and a human-readable
report:

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

## Recommended Workflow

Use Git-SCV before installing, building, testing, or running an unfamiliar
repository.

1. Run `git-scv inspect <repo-path> --out <run-dir>`.
2. Read `report.md` first for the human summary.
3. Check `coverage.json` to see what was inspected, skipped, or left unknown.
4. For each finding, follow the evidence IDs from `findings.json` to
   `evidence.json`.
5. Check `dependencies.json` for direct dependency names and source kinds. Raw
   version ranges, URLs, git addresses, and local paths are not stored.
6. Check `sensitive.json` before raw sensitive-candidate review; it records
   approval and ack confirmation state.
7. Check `gates.json` before model input, install, build, test, or run
   approval; execution candidates also require approval before model input.
8. Use `slices.json` as a path-only reading plan for later model input.
   Sensitive, automatic-execution, and execution-related candidates are excluded
   from default model input until separately approved.
9. Use `review.json` for machine-readable totals, verdict, and required
   actions.
10. Open `report.html` when a browser-friendly run report is useful.
11. Treat `secret-candidate` findings as unresolved review items, not as safe or
   ignored files.
12. Ask for explicit approval before running install, build, test, script, hook,
   binary, or container commands from the inspected repository.

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

## Status

MVP inspector implemented. The CLI can inspect a local repository path and write
the artifact set above without executing commands from the inspected repository.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
