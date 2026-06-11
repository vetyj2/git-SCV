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

## Status

MVP inspector implemented. The CLI can inspect a local repository path and write
the artifact set above without executing commands from the inspected repository.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
