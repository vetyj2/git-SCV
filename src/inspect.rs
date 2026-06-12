//! 검사 흐름 조립.
//!
//! 단계 순서: source → walk → detect → evidence → findings →
//! validate → artifacts → report. run.json 은 마지막에 쓴다.

use crate::cli::InspectArgs;
use crate::errors::ScvError;
use crate::evidence::EvidenceStore;
use crate::model::{
    CoverageArtifact, FindingsArtifact, RunArtifact, RunData, RunStatus, SkipReason, SkipReasons,
    SnapshotInfo, StageRecord, StageStatus, ToolInfo, SCHEMA_VERSION,
};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

pub fn run(args: InspectArgs) -> Result<(), ScvError> {
    run_inner(args, None)
}

pub fn run_with_snapshot(args: InspectArgs, snapshot: SnapshotInfo) -> Result<(), ScvError> {
    run_inner(args, Some(snapshot))
}

fn run_inner(args: InspectArgs, snapshot: Option<SnapshotInfo>) -> Result<(), ScvError> {
    crate::cli::validate(&args)?;
    let started = OffsetDateTime::now_utc();
    let started_at = format_rfc3339(started);
    let run_id = format_run_id(started);
    let command = std::env::args().collect::<Vec<_>>();
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
    let inventory = match crate::walk::walk(root, &run_id) {
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
    let gates = crate::gates::build(&detect_outcome.detections, &sensitive, &run_id);
    let slices = crate::slices::build(&inventory, &sectors, &gates, &run_id);
    let review = crate::review::build(&findings, &gates, &slices, &run_id);
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

    let pre_verify_run = run_artifact(
        &run_id,
        &command,
        &started_at,
        RunStatus::Success,
        0,
        stages.clone(),
    );
    crate::artifacts::write_run_json(&args.out, &pre_verify_run)?;

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
        return Err(ScvError::Validation(items));
    }
    mark_ok(&mut stages, "report");

    let run = run_artifact(
        &run_id,
        &command,
        &started_at,
        RunStatus::Success,
        0,
        stages,
    );
    crate::artifacts::write_run_json(&args.out, &run)?;

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
    CoverageArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
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
    command: &[String],
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
    command: &[String],
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
        command: command.to_vec(),
        started_at: started_at.into(),
        finished_at: format_rfc3339(OffsetDateTime::now_utc()),
        status,
        stages,
        exit_code,
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
