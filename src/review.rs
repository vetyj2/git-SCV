//! 다른 도구가 읽기 쉬운 검토 요약 산출물.
//!
//! 기존 산출물의 집계와 승인 액션만 요약한다. 새로운 파일 읽기나 위험 판단은
//! 하지 않는다.

use crate::model::{
    Category, CoverageArtifact, FindingsArtifact, GateArtifact, Priority, ReviewAction,
    ReviewArtifact, ReviewCounts, SecurityArtifact, SliceArtifact, NO_EXEC_SENTENCE,
    SCHEMA_VERSION,
};
use std::collections::BTreeSet;

pub fn build(
    findings: &FindingsArtifact,
    gates: &GateArtifact,
    slices: &SliceArtifact,
    coverage: &CoverageArtifact,
    dirty_unknown: bool,
    run_id: &str,
) -> ReviewArtifact {
    let high_priority_findings = findings
        .findings
        .iter()
        .filter(|finding| finding.priority() == Priority::High)
        .count() as u64;
    let medium_priority_findings = findings
        .findings
        .iter()
        .filter(|finding| finding.priority() == Priority::Medium)
        .count() as u64;
    let sensitive_findings = findings
        .findings
        .iter()
        .filter(|finding| finding.category() == Category::SecretCandidate)
        .count() as u64;
    let slices_over_token_limit = slices
        .slices
        .iter()
        .filter(|slice| slice.over_token_limit)
        .count() as u64;
    let deep_analysis_candidates = slices
        .slices
        .iter()
        .flat_map(|slice| slice.files.iter())
        .filter(|file| file.deep_analysis_candidate)
        .count() as u64;

    let default_model_excluded_paths = slices
        .slices
        .iter()
        .flat_map(|slice| slice.files.iter())
        .filter(|file| !file.default_model_input)
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let sensitive_gate = gates.sensitive_raw_review.approval_required;
    let execution_gate = gates.execution_model_input_review.approval_required
        || gates.execution_command_review.approval_required;
    let unsupported_surface = coverage_has_insufficient_surface(coverage);
    let insufficient_coverage = !coverage.limit_reason_codes.is_empty() || unsupported_surface;
    let reason_codes = reason_codes(
        findings.findings.len() as u64,
        sensitive_gate,
        execution_gate,
        slices_over_token_limit,
        insufficient_coverage,
        &coverage.limit_reason_codes,
        unsupported_surface,
        dirty_unknown,
    );

    ReviewArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        verdict: verdict(
            findings.findings.len() as u64,
            sensitive_gate,
            execution_gate,
            insufficient_coverage,
        ),
        safe_claim_made: false,
        may_user_run_install: false,
        may_agent_request_run_approval: true,
        may_agent_run_without_user: false,
        reason_codes,
        counts: ReviewCounts {
            findings_total: findings.findings.len() as u64,
            high_priority_findings,
            medium_priority_findings,
            sensitive_candidates: gates.sensitive_candidates.len() as u64,
            automatic_execution_candidates: gates.automatic_execution_candidates.len() as u64,
            execution_related_candidates: gates.execution_related_candidates.len() as u64,
            deep_analysis_candidates,
            slices_total: slices.slices.len() as u64,
            slices_over_token_limit,
        },
        required_actions: required_actions(gates, slices_over_token_limit),
        default_model_excluded_paths,
        note: format!(
            "이 요약은 다른 도구가 읽기 위한 집계다. 발견사항 {sensitive_findings}건을 포함하더라도 안전 보증이 아니며 report.md와 limitations를 함께 읽어야 한다."
        ),
    }
}

fn verdict(
    findings: u64,
    sensitive_gate: bool,
    execution_gate: bool,
    insufficient_coverage: bool,
) -> String {
    if insufficient_coverage {
        "insufficient-coverage".into()
    } else if sensitive_gate || execution_gate {
        "approval-required".into()
    } else if findings > 0 {
        "review-required".into()
    } else {
        "no-blocker-observed".into()
    }
}

fn reason_codes(
    findings: u64,
    sensitive_gate: bool,
    execution_gate: bool,
    slices_over_token_limit: u64,
    insufficient_coverage: bool,
    limit_reason_codes: &[String],
    unsupported_surface: bool,
    dirty_unknown: bool,
) -> Vec<String> {
    let mut codes = Vec::new();
    if insufficient_coverage {
        codes.extend(limit_reason_codes.iter().cloned());
    }
    if unsupported_surface {
        codes.push("unsupported-surface-name-detected".into());
    }
    if sensitive_gate {
        codes.push("sensitive-candidates-present".into());
    }
    if execution_gate {
        codes.push("execution-candidates-present".into());
    }
    if slices_over_token_limit > 0 {
        codes.push("slice-token-limit-exceeded".into());
    }
    if findings > 0 {
        codes.push("findings-present".into());
    }
    if dirty_unknown {
        codes.push("source-dirty-unknown".into());
    }
    if codes.is_empty() {
        codes.push("observed-scope-no-blocker".into());
    }
    codes.sort();
    codes.dedup();
    codes
}

fn coverage_has_insufficient_surface(coverage: &CoverageArtifact) -> bool {
    coverage
        .capabilities
        .iter()
        .any(|capability| capability.verdict_effect.as_deref() == Some("insufficient-coverage"))
}

fn required_actions(gates: &GateArtifact, slices_over_token_limit: u64) -> Vec<ReviewAction> {
    vec![
        ReviewAction {
            id: "sensitive-raw-review".into(),
            required: gates.sensitive_raw_review.approval_required,
            reason: gates.sensitive_raw_review.message.clone(),
            paths: gates.sensitive_raw_review.paths.clone(),
            acknowledgements: gates.sensitive_raw_review.acknowledgements.clone(),
        },
        ReviewAction {
            id: "execution-model-input-review".into(),
            required: gates.execution_model_input_review.approval_required,
            reason: gates.execution_model_input_review.message.clone(),
            paths: gates.execution_model_input_review.paths.clone(),
            acknowledgements: gates.execution_model_input_review.acknowledgements.clone(),
        },
        ReviewAction {
            id: "execution-command-review".into(),
            required: gates.execution_command_review.approval_required,
            reason: gates.execution_command_review.message.clone(),
            paths: Vec::new(),
            acknowledgements: gates.execution_command_review.acknowledgements.clone(),
        },
        ReviewAction {
            id: "oversized-slice-review".into(),
            required: slices_over_token_limit > 0,
            reason:
                "한도를 넘는 단일 파일 슬라이스는 파일 일부 읽기 또는 별도 요약 전략이 필요하다."
                    .into(),
            paths: Vec::new(),
            acknowledgements: Vec::new(),
        },
    ]
}

pub fn build_security(
    findings: &FindingsArtifact,
    review: &ReviewArtifact,
    run_id: &str,
) -> SecurityArtifact {
    SecurityArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        verdict: review.verdict.clone(),
        safe_claim_made: review.safe_claim_made,
        may_user_run_install: review.may_user_run_install,
        may_agent_request_run_approval: review.may_agent_request_run_approval,
        may_agent_run_without_user: review.may_agent_run_without_user,
        reason_codes: review.reason_codes.clone(),
        action_required: review.required_actions.iter().any(|action| action.required),
        no_exec: NO_EXEC_SENTENCE.into(),
        counts: review.counts.clone(),
        required_actions: review.required_actions.clone(),
        default_model_excluded_paths: review.default_model_excluded_paths.clone(),
        limitations: findings.limitations.clone(),
        references: vec![
            "review.json".into(),
            "findings.json".into(),
            "evidence.json".into(),
            "gates.json".into(),
            "slices.json".into(),
            "sensitive.json".into(),
        ],
        note: "다른 도구가 먼저 읽기 쉬운 보안 요약이다. 새 파일을 읽거나 안전을 보증하지 않으며 원천 산출물을 함께 확인해야 한다.".into(),
    }
}
