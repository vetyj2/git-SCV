# Release Discipline

For GitHub tag releases:

1. update `Cargo.toml` and `Cargo.lock` package versions
2. update README install examples to tag-based commands
3. keep `Cargo.lock` included
4. run `cargo fmt --check`, `cargo clippy --lib`, `cargo clippy --all-targets`,
   `cargo test`, secret scan, and version consistency checks
5. tag the release, for example `v0.3.2`
6. verify a fresh install with
   `cargo install --git https://github.com/vetyj2/git-SCV --tag v0.3.2 --locked`
7. publish release notes with schema version, contract version, migration note,
   checksums, known limitations, and install commands

`cargo package --locked` is recommended for GitHub tag releases because it
checks package include boundaries. It is required before any crates.io release
or publish dry-run path.

v0.2 artifacts are not compatible with v0.3 artifact-contract-v2. Re-run
inspection.
