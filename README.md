# Git-SCV

Git-SCV means Source-code-voyager.

Git-SCV is a Rust CLI for no-exec repository inspection. It is intended to help
users and coding agents review an unfamiliar repository before installing,
building, testing, or running it.

Git-SCV is not ready for real repository trust decisions yet.

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

Planned command:

```sh
git-scv inspect <repo-path> --out <run-dir>
```

Git-SCV must not execute install, build, test, script, hook, binary, or container
commands from the inspected repository by default.

The run directory is intended to contain machine-readable artifacts and a
human-readable report:

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

Early implementation scaffold. The public repository contains the installable
package source and minimal usage notes.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
