//! 검사 흐름 조립.
//!
//! 단계 순서: source → walk → detect → evidence → findings →
//! sensitive → validate → artifacts → report. run.json 은 마지막에 쓴다.

use crate::cli::InspectArgs;
use crate::errors::ScvError;
use crate::evidence::EvidenceStore;
use crate::model::{
    CoverageArtifact, Entry, FindingsArtifact, PromptInjectionSurface, RuleId, RunArtifact,
    RunCommand, RunData, RunStatus, SkipReason, SkipReasons, SnapshotInfo, StageRecord,
    StageStatus, SurfaceCapability, ToolInfo, SCHEMA_VERSION,
};
use crate::redaction::{redact_cli_arg, ArgRole};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

pub fn run(args: InspectArgs) -> Result<(), ScvError> {
    let command = inspect_command(&args);
    run_inner(args, None, command)
}

pub fn run_with_snapshot(
    args: InspectArgs,
    snapshot: SnapshotInfo,
    command: RunCommand,
) -> Result<(), ScvError> {
    run_inner(args, Some(snapshot), command)
}

fn run_inner(
    args: InspectArgs,
    snapshot: Option<SnapshotInfo>,
    command: RunCommand,
) -> Result<(), ScvError> {
    crate::cli::validate(&args)?;
    let started = OffsetDateTime::now_utc();
    let started_at = format_rfc3339(started);
    let run_id = format_run_id(started);
    let raw_input = args.repo_path.display().to_string();
    let mut stages = initial_stages();

    fs::create_dir_all(&args.out).map_err(|err| {
        ScvError::Inspect(format!(
            "inspect: 출력 디렉터리를 만들지 못했다: {}: {err}",
            args.out.display()
        ))
    })?;

    let (mut source, dirty_unknown) =
        match crate::source::identify(&raw_input, &args.repo_path, &run_id) {
            Ok(value) => {
                mark_ok(&mut stages, "source");
                value
            }
            Err(err) => {
                return fail(
                    &args.out,
                    &run_id,
                    &command,
                    &started_at,
                    stages,
                    "source",
                    err,
                )
            }
        };
    source.snapshot = snapshot;

    let root = Path::new(&source.resolved_path);
    let mut inventory = match crate::walk::walk(root, &run_id) {
        Ok(value) => {
            mark_ok(&mut stages, "walk");
            value
        }
        Err(err) => {
            return fail(
                &args.out,
                &run_id,
                &command,
                &started_at,
                stages,
                "walk",
                err,
            )
        }
    };

    let detect_outcome = match crate::detect::detect(&inventory, root) {
        Ok(value) => {
            mark_ok(&mut stages, "detect");
            value
        }
        Err(err) => {
            return fail(
                &args.out,
                &run_id,
                &command,
                &started_at,
                stages,
                "detect",
                err,
            )
        }
    };

    let coverage = build_coverage(&inventory, &detect_outcome, &run_id);
    let mut evidence_store = EvidenceStore::new();
    let findings_vec = match crate::findings::build(&detect_outcome.detections, &mut evidence_store)
    {
        Ok(value) => {
            mark_ok(&mut stages, "evidence");
            mark_ok(&mut stages, "findings");
            value
        }
        Err(err) => {
            return fail(
                &args.out,
                &run_id,
                &command,
                &started_at,
                stages,
                "findings",
                err,
            )
        }
    };
    let limitations = crate::findings::limitations(
        dirty_unknown,
        &detect_outcome.limitations,
        findings_vec.is_empty() || coverage.files_read == 0,
    );
    let evidence = evidence_store.into_artifact(&run_id);
    let findings = FindingsArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.clone(),
        findings: findings_vec,
        limitations,
    };
    let dependencies = crate::dependencies::build(&detect_outcome, &run_id);
    let sectors = crate::sectors::build(&inventory, &detect_outcome.detections, &run_id);
    let sensitive =
        match crate::sensitive::build(&inventory, &detect_outcome.detections, root, &args, &run_id)
        {
            Ok(value) => {
                mark_ok(&mut stages, "sensitive");
                value
            }
            Err(err) => {
                return fail(
                    &args.out,
                    &run_id,
                    &command,
                    &started_at,
                    stages,
                    "sensitive",
                    err,
                )
            }
        };
    source.source_fingerprint = Some(crate::source::fingerprint(
        &source,
        &inventory,
        &sensitive,
        root,
        &started_at,
    ));
    let gates = crate::gates::build(&detect_outcome.detections, &sensitive, &run_id);
    let slices = crate::slices::build(&inventory, &sectors, &gates, &run_id);
    let connection_graph = crate::graph::connection_graph(&inventory, &gates, &slices, &run_id);
    let analysis_plan = crate::graph::analysis_plan(&inventory, &gates, &sensitive, &run_id);
    let review = crate::review::build(
        &findings,
        &gates,
        &slices,
        &coverage,
        dirty_unknown,
        &run_id,
    );
    let security = crate::review::build_security(&findings, &review, &run_id);
    let cross_unit_analysis =
        crate::synthesis::cross_unit_analysis(&connection_graph, &gates, &review, &run_id);
    let synthesis =
        crate::synthesis::synthesis(&review, &coverage, &gates, &cross_unit_analysis, &run_id);
    let followup_plan = crate::synthesis::followup_plan(&review, &cross_unit_analysis, &run_id);
    crate::source::apply_path_privacy(&mut source, &mut inventory, args.path_privacy);
    let finished_at = format_rfc3339(OffsetDateTime::now_utc());

    let mut data = RunData {
        run_id: run_id.clone(),
        started_at: started_at.clone(),
        finished_at,
        command: command.clone(),
        source,
        inventory,
        coverage,
        evidence,
        findings,
        dependencies,
        sectors,
        sensitive,
        gates,
        slices,
        review,
        security,
        connection_graph,
        analysis_plan,
        cross_unit_analysis,
        synthesis,
        followup_plan,
        report_md: String::new(),
    };
    data.report_md = crate::report::render(&data);

    if let Err(items) = crate::validate::validate(&data) {
        let err = ScvError::Validation(items.clone());
        mark_failed(&mut stages, "validate", err.user_message());
        let run = run_artifact(
            &run_id,
            &command,
            &started_at,
            RunStatus::Invalid,
            err.exit_code(),
            stages,
        );
        crate::artifacts::write_run_json(&args.out, &run)?;
        return Err(ScvError::Validation(items));
    }
    mark_ok(&mut stages, "validate");

    if let Err(err) = crate::artifacts::write_all(&args.out, &data) {
        return fail(
            &args.out,
            &run_id,
            &command,
            &started_at,
            stages,
            "artifacts",
            err,
        );
    }
    mark_ok(&mut stages, "artifacts");
    mark_ok(&mut stages, "report");

    let run = run_artifact(
        &run_id,
        &command,
        &started_at,
        RunStatus::Success,
        0,
        stages.clone(),
    );
    crate::artifacts::write_run_json(&args.out, &run)?;
    crate::artifacts::write_artifact_manifest(&args.out, &data)?;
    if let Err(err) = crate::artifacts::write_brief_artifacts(&args.out, &data) {
        return fail(
            &args.out,
            &run_id,
            &command,
            &started_at,
            stages,
            "artifacts",
            err,
        );
    }

    if let Err(items) = crate::validate::verify_outputs(&args.out) {
        let err = ScvError::Validation(items.clone());
        mark_failed(&mut stages, "report", err.user_message());
        let run = run_artifact(
            &run_id,
            &command,
            &started_at,
            RunStatus::Invalid,
            err.exit_code(),
            stages,
        );
        crate::artifacts::write_run_json(&args.out, &run)?;
        crate::artifacts::write_artifact_manifest(&args.out, &data)?;
        crate::artifacts::write_brief_artifacts(&args.out, &data)?;
        return Err(ScvError::Validation(items));
    }

    let repo = fs::canonicalize(&args.repo_path).map_err(|err| {
        ScvError::Inspect(format!(
            "inspect: 검사 대상 경로를 정규화하지 못했다: {}: {err}",
            args.repo_path.display()
        ))
    })?;
    let out = fs::canonicalize(&args.out).map_err(|err| {
        ScvError::Inspect(format!(
            "inspect: 출력 경로를 정규화하지 못했다: {}: {err}",
            args.out.display()
        ))
    })?;
    println!("검사 완료: {}", repo.display());
    println!("산출물: {}", out.display());
    Ok(())
}

fn build_coverage(
    inventory: &crate::model::InventoryArtifact,
    outcome: &crate::model::DetectOutcome,
    run_id: &str,
) -> CoverageArtifact {
    let mut skip_reasons = SkipReasons {
        binary: outcome.binary_skips,
        ..SkipReasons::default()
    };
    for item in &inventory.skipped {
        match item.reason {
            SkipReason::Symlink => skip_reasons.symlink += 1,
            SkipReason::Unreadable => skip_reasons.unreadable += 1,
            SkipReason::ExcludedGitDir => skip_reasons.excluded_git_dir += 1,
        }
    }
    let bytes_read_total = outcome.read_files.iter().map(|item| item.bytes).sum();
    let mut limit_reason_codes = inventory.limits.exceeded_reason_codes.clone();
    limit_reason_codes.extend(outcome.limit_reason_codes.iter().cloned());
    limit_reason_codes.sort();
    limit_reason_codes.dedup();
    CoverageArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        local_limits: inventory.limits.clone(),
        limit_reason_codes,
        capabilities: surface_capabilities(inventory, outcome),
        prompt_injection_surfaces: prompt_injection_surfaces(inventory),
        files_discovered: inventory.totals.discovered,
        files_read: outcome.read_files.len() as u64,
        files_skipped: inventory.totals.skipped,
        bytes_read_total,
        read_files: outcome.read_files.clone(),
        skip_reasons,
        confidence_note:
            "이름 기반 감지가 주 수단이며 내용 열람은 감지 규칙이 지정한 파일로 한정되었다.".into(),
    }
}

fn surface_capabilities(
    inventory: &crate::model::InventoryArtifact,
    outcome: &crate::model::DetectOutcome,
) -> Vec<SurfaceCapability> {
    let mut capabilities = Vec::new();
    if inventory
        .entries
        .iter()
        .any(|entry| entry.path == "package.json")
    {
        let support = if outcome
            .read_files
            .iter()
            .any(|file| file.path == "package.json")
        {
            "parsed"
        } else {
            "name-detected"
        };
        capabilities.push(SurfaceCapability {
            surface: "npm/package.json".into(),
            support: support.into(),
            signals: vec!["scripts".into(), "dependencies".into()],
            raw_values_stored: false,
            verdict_effect: verdict_effect_for_support(support),
        });
    }
    if inventory
        .entries
        .iter()
        .any(|entry| entry.path.starts_with(".github/workflows/"))
    {
        capabilities.push(SurfaceCapability {
            surface: "GitHub Actions workflow".into(),
            support: "name-detected".into(),
            signals: vec!["workflow-path".into()],
            raw_values_stored: false,
            verdict_effect: Some("insufficient-coverage".into()),
        });
    }
    if inventory.entries.iter().any(is_docker_surface) {
        capabilities.push(SurfaceCapability {
            surface: "Dockerfile/Containerfile".into(),
            support: "name-detected".into(),
            signals: vec!["container-definition-name".into()],
            raw_values_stored: false,
            verdict_effect: Some("insufficient-coverage".into()),
        });
    }
    if inventory
        .entries
        .iter()
        .any(|entry| matches!(entry.path.as_str(), "Cargo.toml" | "Cargo.lock"))
    {
        capabilities.push(SurfaceCapability {
            surface: "Rust/Cargo".into(),
            support: "name-detected".into(),
            signals: vec!["manifest-name".into(), "lockfile-name".into()],
            raw_values_stored: false,
            verdict_effect: Some("insufficient-coverage".into()),
        });
    }
    if outcome
        .detections
        .iter()
        .any(|detection| detection.rule == RuleId::D14)
    {
        capabilities.push(SurfaceCapability {
            surface: "additional ecosystem manifest/tool config".into(),
            support: "name-detected".into(),
            signals: vec!["manifest-or-tool-config-name".into()],
            raw_values_stored: false,
            verdict_effect: Some("insufficient-coverage".into()),
        });
    }
    capabilities
}

fn verdict_effect_for_support(support: &str) -> Option<String> {
    if support == "parsed" {
        None
    } else {
        Some("insufficient-coverage".into())
    }
}

fn prompt_injection_surfaces(
    inventory: &crate::model::InventoryArtifact,
) -> Vec<PromptInjectionSurface> {
    inventory
        .entries
        .iter()
        .filter(|entry| is_prompt_injection_surface(entry))
        .map(|entry| PromptInjectionSurface {
            path: entry.path.clone(),
            default_model_input: "allowed-as-untrusted-text".into(),
            agent_must_not_obey: true,
            reason: "Target repository instruction file is analysis subject, not system/developer instruction.".into(),
        })
        .collect()
}

fn is_docker_surface(entry: &Entry) -> bool {
    matches!(entry.path.as_str(), "Dockerfile" | "Containerfile")
        || entry.path.ends_with("/Dockerfile")
        || entry.path.ends_with("/Containerfile")
}

fn is_prompt_injection_surface(entry: &Entry) -> bool {
    matches!(
        entry.path.as_str(),
        "AGENTS.md"
            | "CLAUDE.md"
            | ".github/copilot-instructions.md"
            | "CONTRIBUTING.md"
            | "docs/setup.md"
            | "docs/install.md"
    ) || entry.path.starts_with(".cursor/rules")
        || entry.path.starts_with(".github/ISSUE_TEMPLATE/")
}

fn initial_stages() -> Vec<StageRecord> {
    [
        "source",
        "walk",
        "detect",
        "evidence",
        "findings",
        "sensitive",
        "validate",
        "artifacts",
        "report",
    ]
    .into_iter()
    .map(|name| StageRecord {
        name: name.into(),
        status: StageStatus::Skipped,
        error: None,
    })
    .collect()
}

fn mark_ok(stages: &mut [StageRecord], name: &str) {
    if let Some(stage) = stages.iter_mut().find(|stage| stage.name == name) {
        stage.status = StageStatus::Ok;
        stage.error = None;
    }
}

fn mark_failed(stages: &mut [StageRecord], name: &str, error: String) {
    if let Some(stage) = stages.iter_mut().find(|stage| stage.name == name) {
        stage.status = StageStatus::Failed;
        stage.error = Some(error);
    }
}

fn fail(
    out: &Path,
    run_id: &str,
    command: &RunCommand,
    started_at: &str,
    mut stages: Vec<StageRecord>,
    stage: &str,
    err: ScvError,
) -> Result<(), ScvError> {
    mark_failed(&mut stages, stage, err.user_message());
    let run = run_artifact(
        run_id,
        command,
        started_at,
        RunStatus::Failed,
        err.exit_code(),
        stages,
    );
    crate::artifacts::write_run_json(out, &run)?;
    Err(err)
}

fn run_artifact(
    run_id: &str,
    command: &RunCommand,
    started_at: &str,
    status: RunStatus,
    exit_code: i32,
    stages: Vec<StageRecord>,
) -> RunArtifact {
    RunArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        tool: ToolInfo {
            name: "git-scv".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        command: command.clone(),
        started_at: started_at.into(),
        finished_at: format_rfc3339(OffsetDateTime::now_utc()),
        status,
        stages,
        exit_code,
    }
}

fn inspect_command(args: &InspectArgs) -> RunCommand {
    let mut args_redacted = vec![
        redact_cli_arg(&args.repo_path.display().to_string(), ArgRole::Path).into_string(),
        "--out".into(),
        redact_cli_arg(&args.out.display().to_string(), ArgRole::Path).into_string(),
        "--sensitive-mode".into(),
        sensitive_mode_label(args.sensitive_mode).into(),
        "--path-privacy".into(),
        path_privacy_mode_label(args.path_privacy).into(),
    ];
    if args.approve_sensitive_review {
        args_redacted.push("--approve-sensitive-review".into());
    }
    if args.sensitive_review_ack.is_some() {
        args_redacted.push("--sensitive-review-ack".into());
        args_redacted.push("<ack>".into());
    }
    if args.approve_sensitive_raw {
        args_redacted.push("--approve-sensitive-raw".into());
    }
    if args.sensitive_raw_ack.is_some() {
        args_redacted.push("--sensitive-raw-ack".into());
        args_redacted.push("<ack>".into());
    }
    for _ in &args.sensitive_paths {
        args_redacted.push("--sensitive-path".into());
        args_redacted.push("<repo-relative-path>".into());
    }

    RunCommand {
        program: "git-scv".into(),
        subcommand: "inspect".into(),
        args_redacted,
        raw_args_stored: false,
    }
}

fn sensitive_mode_label(mode: crate::model::SensitiveReviewMode) -> &'static str {
    match mode {
        crate::model::SensitiveReviewMode::Exclude => "exclude",
        crate::model::SensitiveReviewMode::RedactedSummary => "redacted-summary",
        crate::model::SensitiveReviewMode::ApprovedRaw => "approved-raw",
    }
}

fn path_privacy_mode_label(mode: crate::model::PathPrivacyMode) -> &'static str {
    match mode {
        crate::model::PathPrivacyMode::RepoRelative => "repo-relative",
        crate::model::PathPrivacyMode::RedactedAbsolute => "redacted-absolute",
        crate::model::PathPrivacyMode::Absolute => "absolute",
    }
}

pub fn snapshot_command(args: &crate::cli::SnapshotArgs) -> RunCommand {
    let mut args_redacted = vec![
        redact_cli_arg(&args.url, ArgRole::ArchiveUrl).into_string(),
        "--out".into(),
        redact_cli_arg(&args.out.display().to_string(), ArgRole::Path).into_string(),
    ];
    if args.sha256.is_some() {
        args_redacted.push("--sha256".into());
        args_redacted.push(
            redact_cli_arg(args.sha256.as_deref().unwrap_or_default(), ArgRole::Sha256)
                .into_string(),
        );
    }

    RunCommand {
        program: "git-scv".into(),
        subcommand: "snapshot".into(),
        args_redacted,
        raw_args_stored: false,
    }
}

fn format_rfc3339(time: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

fn format_run_id(time: OffsetDateTime) -> String {
    format!(
        "scv-{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}
