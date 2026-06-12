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

Install Git-SCV from GitHub:

```sh
cargo install --git https://github.com/vetyj2/git-SCV --locked
```

Or install it from a local checkout:

```sh
cargo install --path . --locked
```

## Build

```sh
cargo build
```

## Usage

```sh
git-scv inspect <repo-path> --out <run-dir>
git-scv snapshot <archive-url> --out <snapshot-dir> --sha256 <hex>
```

`<repo-path>` must be a local directory. Repository URL inputs such as
`https://...`, `git@host:owner/repo.git`, and `file://...` are rejected by
`inspect`. Download or clone the repository first, then inspect that local
directory.

The `inspect` command never fetches from a remote. The separate `snapshot`
command downloads an HTTPS archive in memory, checks it against a user-provided
SHA-256 digest, and extracts only safe `.zip`, `.tar.gz`, or `.tgz` entries into
`<snapshot-dir>/source`, then writes the normal inspection artifacts to
`<snapshot-dir>/run`. Its `--sha256` value must be a 64-character hex SHA-256
digest, its URL must start with `https://`, it must not include URL user
information, and its output directory must be new or empty. URL validation errors
redact user information and query or fragment details. Snapshot inspection writes
sanitized snapshot metadata to `run/source.json`, including the archive URL
without query or fragment details, the verified SHA-256 digest, archive format,
and extracted source path.

For detailed command examples, sensitive-candidate modes, and artifact reading
order, see [USAGE.md](USAGE.md).

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
security.json
report.md
report.html
```

## Recommended Use

Use Git-SCV before installing, building, testing, or running an unfamiliar
repository.

1. Use `inspect` when the repository is already on disk.
2. Use `snapshot` only when you have an HTTPS archive URL and a SHA-256 digest
   verified through a separate channel.
3. Read `report.md` or `report.html` first, including the required action list,
   then check `source.json`, `inventory.json`, `coverage.json`,
   `findings.json`, `evidence.json`, `dependencies.json`, `sensitive.json`,
   `gates.json`, `slices.json`, `review.json`, and `security.json` before
   approving any next action.
4. Treat `secret-candidate` findings as unresolved review items, not as safe or
   ignored files.
5. Ask for explicit approval before running install, build, test, script, hook,
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

v0.2.2 prepares no-exec local and verified HTTPS snapshot inspection, sensitive
candidate review gates, path-only model input slices, human and HTML reports,
machine-readable security summaries, and Cargo package/install checks.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
