# Release Discipline

For schema-breaking releases:

1. update `Cargo.toml` and `Cargo.lock` package versions
2. update README install examples to tag-based commands
3. keep `Cargo.lock` included
4. run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo package --locked`
5. tag the release, for example `v0.3.0`
6. publish release notes with schema version, contract version, migration note,
   checksums, known limitations, and install commands

v0.2 artifacts are not compatible with v0.3 artifact-contract-v2. Re-run
inspection.
