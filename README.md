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

The output directory must be new or empty. Git-SCV does not execute install,
build, test, script, hook, binary, or container commands from the inspected
repository.

The run directory contains machine-readable artifacts and a human-readable
report:

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

## Recommended Workflow

Use Git-SCV before installing, building, testing, or running an unfamiliar
repository.

1. Run `git-scv inspect <repo-path> --out <run-dir>`.
2. Read `report.md` first for the human summary.
3. Check `coverage.json` to see what was inspected, skipped, or left unknown.
4. For each finding, follow the evidence IDs from `findings.json` to
   `evidence.json`.
5. Treat `secret-candidate` findings as unresolved review items, not as safe or
   ignored files.
6. Ask for explicit approval before running install, build, test, script, hook,
   binary, or container commands from the inspected repository.

## Sensitive Candidates

Git-SCV treats files such as `.env`, private-key names, certificates, and names
containing `secret` or `credential` as sensitive candidates. The default
inspection reports those paths without reading or copying their contents.

Sensitive candidates are not ignored and are not treated as safe. They are
reported as unresolved review items, especially when a repository might hide an
executable script behind a sensitive-looking name. Any later raw-content
analysis should require explicit, path-specific user approval outside the
default inspection.

## Status

MVP inspector implemented. The CLI can inspect a local repository path and write
the artifact set above without executing commands from the inspected repository.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
