//! 에이전트가 긴 보고서를 생략하지 않도록 먼저 읽는 필수 브리핑.
//!
//! 대상 저장소 파일은 읽지 않고 이미 생성된 JSON 산출물만 요약한다.

use crate::cli::BriefArgs;
use crate::errors::ScvError;
use serde::Deserialize;
use std::fs;
use std::path::Path;

const PATH_PREVIEW_LIMIT: usize = 20;

#[derive(Deserialize)]
struct Counts {
    findings_total: u64,
    high_priority_findings: u64,
    medium_priority_findings: u64,
    sensitive_candidates: u64,
    automatic_execution_candidates: u64,
    execution_related_candidates: u64,
    deep_analysis_candidates: u64,
    slices_total: u64,
    slices_over_token_limit: u64,
}

#[derive(Deserialize)]
struct Action {
    id: String,
    required: bool,
    reason: String,
    paths: Vec<String>,
    acknowledgements: Vec<String>,
}

#[derive(Deserialize)]
struct Security {
    counts: Counts,
    required_actions: Vec<Action>,
    default_model_excluded_paths: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Deserialize)]
struct BriefSummary {
    run_id: String,
    artifact_manifest_sha256: String,
    source_fingerprint_hash: String,
    verdict: String,
    safe_claim_made: bool,
    may_user_run_install: bool,
    may_agent_request_run_approval: bool,
    may_agent_run_without_user: bool,
    action_required: bool,
    reason_codes: Vec<String>,
    next_step_blocked_until: Vec<String>,
    no_exec_statement: String,
}

#[derive(Deserialize)]
struct SliceFile {
    path: String,
    default_model_input: bool,
    sensitive_candidate: bool,
    automatic_execution_candidate: bool,
    execution_related_candidate: bool,
    deep_analysis_candidate: bool,
}

#[derive(Deserialize)]
struct Slice {
    id: String,
    files: Vec<SliceFile>,
    over_token_limit: bool,
    requires_sensitive_raw_approval: bool,
    requires_execution_approval: bool,
}

#[derive(Deserialize)]
struct Slices {
    slices: Vec<Slice>,
}

#[derive(Default)]
struct SliceSummary {
    total_files: usize,
    default_model_files: usize,
    blocked_files: Vec<String>,
    sensitive_files: Vec<String>,
    execution_files: Vec<String>,
    deep_analysis_files: Vec<String>,
    oversized_slices: Vec<String>,
    gated_slices: Vec<String>,
}

pub fn run(args: BriefArgs) -> Result<(), ScvError> {
    let run_dir = args.run_dir;
    if !run_dir.exists() {
        return Err(ScvError::Usage(format!(
            "오류: brief 산출물 디렉터리가 존재하지 않는다: {}",
            run_dir.display()
        )));
    }
    if !run_dir.is_dir() {
        return Err(ScvError::Usage(format!(
            "오류: brief 산출물 경로가 디렉터리가 아니다: {}",
            run_dir.display()
        )));
    }

    let brief: BriefSummary = read_json(&run_dir, "brief.json")?;
    let security: Security = read_json(&run_dir, "security.json")?;
    let slices: Slices = read_json(&run_dir, "slices.json")?;
    let slice_summary = summarize_slices(&slices);

    println!("git-scv 필수 에이전트 브리핑");
    println!("run_dir={}", run_dir.display());
    println!("run_id={}", brief.run_id);
    println!(
        "artifact_manifest_sha256={}",
        brief.artifact_manifest_sha256
    );
    println!("source_fingerprint_hash={}", brief.source_fingerprint_hash);
    println!("verdict={}", brief.verdict);
    println!("safe_claim_made={}", brief.safe_claim_made);
    println!("may_user_run_install={}", brief.may_user_run_install);
    println!(
        "may_agent_request_run_approval={}",
        brief.may_agent_request_run_approval
    );
    println!(
        "may_agent_run_without_user={}",
        brief.may_agent_run_without_user
    );
    println!("reason_codes={}", brief.reason_codes.join(","));
    println!("action_required={}", brief.action_required);
    println!(
        "next_step_blocked_until={}",
        brief.next_step_blocked_until.join(",")
    );
    println!("no_exec_statement={}", brief.no_exec_statement);
    println!(
        "counts=findings:{},high:{},medium:{},sensitive:{},auto_exec:{},exec_related:{},deep_analysis:{},slices:{},oversized_slices:{}",
        security.counts.findings_total,
        security.counts.high_priority_findings,
        security.counts.medium_priority_findings,
        security.counts.sensitive_candidates,
        security.counts.automatic_execution_candidates,
        security.counts.execution_related_candidates,
        security.counts.deep_analysis_candidates,
        security.counts.slices_total,
        security.counts.slices_over_token_limit
    );
    println!("required_actions:");
    for action in &security.required_actions {
        println!(
            "- id={} required={} paths={} acknowledgements={}",
            action.id,
            action.required,
            action.paths.len(),
            action.acknowledgements.join(",")
        );
        if action.required {
            println!("  reason={}", action.reason);
            print_paths("  path", &action.paths);
        }
    }
    println!(
        "default_model_input=allowed_files:{},blocked_files:{}",
        slice_summary.default_model_files,
        slice_summary.blocked_files.len()
    );
    println!(
        "default_model_excluded_paths_count={}",
        security.default_model_excluded_paths.len()
    );
    print_paths(
        "default_model_excluded_path",
        &security.default_model_excluded_paths,
    );
    println!("slice_guards:");
    println!(
        "- sensitive_candidate_files={}",
        slice_summary.sensitive_files.len()
    );
    print_paths("  sensitive_path", &slice_summary.sensitive_files);
    println!(
        "- execution_candidate_files={}",
        slice_summary.execution_files.len()
    );
    print_paths("  execution_path", &slice_summary.execution_files);
    println!(
        "- deep_analysis_candidate_files={}",
        slice_summary.deep_analysis_files.len()
    );
    print_paths("  deep_analysis_path", &slice_summary.deep_analysis_files);
    println!(
        "- oversized_slices={}",
        slice_summary.oversized_slices.len()
    );
    print_paths("  oversized_slice", &slice_summary.oversized_slices);
    println!("- gated_slices={}", slice_summary.gated_slices.len());
    print_paths("  gated_slice", &slice_summary.gated_slices);
    println!("limitations_count={}", security.limitations.len());
    print_paths("limitation", &security.limitations);
    println!("mandatory_agent_rules:");
    println!("- 사용자에게 verdict, action_required, required_actions를 먼저 요약한다.");
    println!("- 모델 입력은 slices.json에서 default_model_input=true인 파일만 기본 허용한다.");
    println!("- 민감 후보와 실행 후보는 경로를 먼저 보여주고 명시 승인 전에는 원문 입력 또는 실행을 하지 않는다.");
    println!("- 이 브리핑은 전체 보고서 대체물이 아니며 report.md와 원천 JSON 확인을 요구한다.");
    println!(
        "agent_read_receipt=git-scv-brief:v2:{}:{}:{}:{}:{}",
        brief.artifact_manifest_sha256,
        brief.source_fingerprint_hash,
        brief.verdict,
        security
            .required_actions
            .iter()
            .filter(|a| a.required)
            .count(),
        slice_summary.blocked_files.len()
    );

    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(run_dir: &Path, name: &str) -> Result<T, ScvError> {
    let path = run_dir.join(name);
    let bytes = fs::read(&path).map_err(|err| {
        ScvError::Inspect(format!(
            "brief: 산출물 파일을 읽지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ScvError::Inspect(format!(
            "brief: 산출물 JSON을 해석하지 못했다: {}: {err}",
            path.display()
        ))
    })
}

fn summarize_slices(slices: &Slices) -> SliceSummary {
    let mut summary = SliceSummary::default();

    for slice in &slices.slices {
        if slice.over_token_limit {
            summary.oversized_slices.push(slice.id.clone());
        }
        if slice.requires_sensitive_raw_approval || slice.requires_execution_approval {
            summary.gated_slices.push(slice.id.clone());
        }
        for file in &slice.files {
            summary.total_files += 1;
            if file.default_model_input {
                summary.default_model_files += 1;
            } else {
                summary.blocked_files.push(file.path.clone());
            }
            if file.sensitive_candidate {
                summary.sensitive_files.push(file.path.clone());
            }
            if file.automatic_execution_candidate || file.execution_related_candidate {
                summary.execution_files.push(file.path.clone());
            }
            if file.deep_analysis_candidate {
                summary.deep_analysis_files.push(file.path.clone());
            }
        }
    }

    summary.blocked_files.sort();
    summary.blocked_files.dedup();
    summary.sensitive_files.sort();
    summary.sensitive_files.dedup();
    summary.execution_files.sort();
    summary.execution_files.dedup();
    summary.deep_analysis_files.sort();
    summary.deep_analysis_files.dedup();
    summary.oversized_slices.sort();
    summary.oversized_slices.dedup();
    summary.gated_slices.sort();
    summary.gated_slices.dedup();

    summary
}

fn print_paths(label: &str, paths: &[String]) {
    for path in paths.iter().take(PATH_PREVIEW_LIMIT) {
        println!("{label}={path}");
    }
    if paths.len() > PATH_PREVIEW_LIMIT {
        println!("{label}_remaining={}", paths.len() - PATH_PREVIEW_LIMIT);
    }
}
