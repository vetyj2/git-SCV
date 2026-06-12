//! 다른 도구가 읽기 쉬운 검토 요약 산출물.
//!
//! 기존 산출물의 집계와 승인 액션만 요약한다. 새로운 파일 읽기나 위험 판단은
//! 하지 않는다.

use crate::model::{
    Category, FindingsArtifact, GateArtifact, Priority, ReviewAction, ReviewArtifact, ReviewCounts,
    SecurityArtifact, SliceArtifact, NO_EXEC_SENTENCE, SCHEMA_VERSION,
};
use std::collections::BTreeSet;

pub fn build(
    findings: &FindingsArtifact,
    gates: &GateArtifact,
    slices: &SliceArtifact,
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

    ReviewArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        verdict: verdict(
            findings.findings.len() as u64,
            gates.sensitive_raw_review.approval_required,
            gates.execution_review.approval_required,
        ),
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

fn verdict(findings: u64, sensitive_gate: bool, execution_gate: bool) -> String {
    if sensitive_gate || execution_gate {
        "approval-required".into()
    } else if findings > 0 {
        "review-required".into()
    } else {
        "no-findings-within-observed-scope".into()
    }
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
            id: "execution-review".into(),
            required: gates.execution_review.approval_required,
            reason: gates.execution_review.message.clone(),
            paths: gates.execution_review.paths.clone(),
            acknowledgements: gates.execution_review.acknowledgements.clone(),
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
