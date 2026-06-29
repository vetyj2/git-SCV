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
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.0 --locked
cargo install --git https://github.com/vetyj2/git-SCV --rev <commit-sha> --locked
cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.1 --locked --force
git-scv --version
```

Installing from a moving branch is an advanced, unstable bootstrap path:

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
git-scv brief <run-dir>
git-scv receipt create <run-dir> --agent Hermes --summary-file <summary.md> --summarized-to-user --blocked-actions-acknowledged
git-scv case create <repo-path>
git-scv case verify-source <case-id>
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

For Hermes-style agent integration, per-repository temporary report packages,
cleanup commands, and install/update/uninstall commands, see
[docs/HERMES.md](docs/HERMES.md). A convenience wrapper is available at
[`scripts/git-scv-hermes.sh`](scripts/git-scv-hermes.sh).
The v0.3 implementation boundary is summarized in
[docs/IMPLEMENTATION_STATUS_2026-06-29.md](docs/IMPLEMENTATION_STATUS_2026-06-29.md).

The output directory must be new or empty. Git-SCV does not execute install,
build, test, script, hook, binary, or container commands from the inspected
repository.

When Git-SCV records git remote URLs in `source.json`, URL user information is
redacted so access tokens are not copied into artifacts.

The run directory contains machine-readable artifacts and a human-readable
report:

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
agent_receipt.json (created after `git-scv receipt create`)
report.md
report.html
```

## Recommended Use

Use Git-SCV before installing, building, testing, or running an unfamiliar
repository.

1. Use `inspect` when the repository is already on disk.
2. Use `snapshot` only when you have an HTTPS archive URL and a SHA-256 digest
   verified through a separate channel.
3. Run `git-scv brief <run-dir>` first and summarize its verdict, required
   actions, model-excluded path count, `artifact_manifest_sha256`,
   `source_fingerprint_hash`, and `agent_read_receipt` before any next action.
4. Read `report.md` or `report.html`, including the required action list, then
   check `source.json`, `inventory.json`, `coverage.json`,
   `findings.json`, `evidence.json`, `dependencies.json`, `sensitive.json`,
   `gates.json`, `slices.json`, `review.json`, `security.json`,
   `connection_graph.json`, `analysis_plan.json`, `cross_unit_analysis.json`,
   `synthesis.json`, and `followup_plan.json` before approving any next action.
5. Treat `secret-candidate` findings as unresolved review items, not as safe or
   ignored files.
6. When using case packages, run `git-scv case verify-source <case-id>` before
   any install/build/test/run approval request.
7. Ask for explicit approval before running install, build, test, script, hook,
   binary, workflow, package-manager, or container commands from the inspected
   repository.
8. For agent-supplied unit analyses, run `git-scv validate-unit <run-dir>
   unit-analysis/U0001.json` or `git-scv validate-units <run-dir>` before
   treating unit claims as part of the case package. These validators check
   schema shape, evidence refs, and path boundaries; they do not prove semantic
   truth or malware absence.

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

## Cleanup And Uninstall

Git-SCV writes artifacts only to the output directories you choose with `--out`.
After reviewing a report package, remove that directory directly:

```sh
rm -rf <run-dir>
rm -rf <snapshot-dir>
```

Managed case packages can be removed with:

```sh
git-scv case delete <case-id> --ack delete-git-scv-case
git-scv case prune --all --ack delete-all-git-scv-cases
```

If you use the Hermes harness script, it creates per-case packages under
`${TMPDIR:-/tmp}/git-scv-cases` by default:

```sh
scripts/git-scv-hermes.sh cleanup <case-dir> --ack delete-git-scv-case
scripts/git-scv-hermes.sh cleanup-all --ack delete-all-git-scv-cases
```

Uninstall the binary installed by Cargo:

```sh
cargo uninstall git-scv
```

Git-SCV does not create background services, shell hooks, git hooks, or global
configuration.

## Status

v0.3.0 is a schema-breaking artifact-contract-v2 release. v0.2 artifacts are
not migrated; re-run inspection. Git-SCV does not claim repositories are safe,
clean, trusted, secure, safe-to-install, or safe-to-run.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
