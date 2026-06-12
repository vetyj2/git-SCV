//! CLI entrypoint.

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e.user_message());
        std::process::exit(e.exit_code());
    }
}

fn run() -> Result<(), git_scv::errors::ScvError> {
    match git_scv::cli::parse() {
        git_scv::cli::Invocation::Inspect(args) => git_scv::inspect::run(args),
        git_scv::cli::Invocation::Snapshot(args) => git_scv::snapshot::run(args),
    }
}
