//! CLI entrypoint.

fn main() {
    let args = git_scv::cli::parse();
    if let Err(e) = git_scv::inspect::run(args) {
        eprintln!("{}", e.user_message());
        std::process::exit(e.exit_code());
    }
}
