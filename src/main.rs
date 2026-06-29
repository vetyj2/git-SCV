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
        git_scv::cli::Invocation::Brief(args) => git_scv::brief::run(args),
        git_scv::cli::Invocation::ReceiptCreate(args) => git_scv::receipt::create(args),
        git_scv::cli::Invocation::CaseCreate(args) => git_scv::case::create(args),
        git_scv::cli::Invocation::CaseList => git_scv::case::list(),
        git_scv::cli::Invocation::CaseShow(args) => git_scv::case::show(args),
        git_scv::cli::Invocation::CaseBrief(args) => git_scv::case::brief(args),
        git_scv::cli::Invocation::CaseVerifySource(args) => git_scv::case::verify_source(args),
        git_scv::cli::Invocation::CaseStatus(args) => git_scv::case::status(args),
        git_scv::cli::Invocation::CaseDelete(args) => git_scv::case::delete(args),
        git_scv::cli::Invocation::CasePrune(args) => git_scv::case::prune(args),
        git_scv::cli::Invocation::CaseDoctor => git_scv::case::doctor(),
        git_scv::cli::Invocation::ValidateUnit(args) => git_scv::unit_analysis::validate_unit(args),
        git_scv::cli::Invocation::ValidateUnits(args) => {
            git_scv::unit_analysis::validate_units(args)
        }
        git_scv::cli::Invocation::Synthesize(args) => git_scv::unit_analysis::synthesize(args),
        git_scv::cli::Invocation::FollowupPlan(args) => git_scv::unit_analysis::followup_plan(args),
        git_scv::cli::Invocation::ValidateFollowup(args) => {
            git_scv::unit_analysis::validate_followup(args)
        }
    }
}
