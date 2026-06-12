//! 검증 관문.
//!
//! validate: 쓰기 전 메모리 검증 (V02–V14)
//! verify_outputs: 쓰기 후 디스크 검증 (V01, V05) — 이 함수만 IO 예외다
//! (architecture.md 1절). 실패 문자열은 사양의 표 그대로 만든다.

use crate::model::{Priority, RunData, LOW_CONFIDENCE_SENTENCE, NO_EXEC_SENTENCE, SCHEMA_VERSION};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub fn validate(data: &RunData) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let evidence_ids: BTreeSet<&str> = data
        .evidence
        .evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let dangling: Vec<&str> = data
        .findings
        .findings
        .iter()
        .filter(|finding| {
            finding
                .evidence_ids()
                .iter()
                .any(|id| !evidence_ids.contains(id.as_str()))
        })
        .map(|finding| finding.id())
        .collect();
    if !dangling.is_empty() {
        errors.push(format!("V02: 증거 없는 발견사항: {}", dangling.join(", ")));
    }

    if data.inventory.totals.discovered
        != data.inventory.totals.listed + data.inventory.totals.skipped
    {
        errors.push("V03: 인벤토리 집계 불일치".into());
    }

    let bytes_sum: u64 = data.coverage.read_files.iter().map(|file| file.bytes).sum();
    if bytes_sum != data.coverage.bytes_read_total {
        errors.push("V04: 커버리지 바이트 불일치".into());
    }

    let low_confidence = data.findings.findings.is_empty() || data.coverage.files_read == 0;
    if low_confidence
        && !data
            .findings
            .limitations
            .iter()
            .any(|item| item == LOW_CONFIDENCE_SENTENCE)
    {
        errors.push("V06: 낮은 확신 표시 누락".into());
    }

    let sensitive_paths = data
        .sensitive
        .candidates
        .iter()
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();
    let gate_sensitive_paths = data
        .gates
        .sensitive_candidates
        .iter()
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();
    if sensitive_paths != gate_sensitive_paths {
        errors.push("V07: 민감 후보 게이트 불일치".into());
    }

    let prompt_sensitive_paths = data
        .gates
        .sensitive_raw_review
        .paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let execution_paths = data
        .gates
        .automatic_execution_candidates
        .iter()
        .chain(data.gates.execution_related_candidates.iter())
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();
    let prompt_execution_paths = data
        .gates
        .execution_review
        .paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if prompt_sensitive_paths != gate_sensitive_paths || prompt_execution_paths != execution_paths {
        errors.push("V08: 승인 프롬프트 경로 불일치".into());
    }

    let inventory_files = data
        .inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == crate::model::EntryKind::File)
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut unknown_slice_paths = Vec::new();
    let mut unsafe_sensitive_slice_paths = Vec::new();
    let mut slice_flag_mismatch = Vec::new();
    for slice in &data.slices.slices {
        let requires_sensitive = slice.files.iter().any(|file| file.sensitive_candidate);
        let requires_execution = slice
            .files
            .iter()
            .any(|file| file.automatic_execution_candidate || file.execution_related_candidate);
        if slice.requires_sensitive_raw_approval != requires_sensitive
            || slice.requires_execution_approval != requires_execution
        {
            slice_flag_mismatch.push(slice.id.as_str());
        }
        for file in &slice.files {
            if !inventory_files.contains(file.path.as_str()) {
                unknown_slice_paths.push(file.path.as_str());
            }
            if file.sensitive_candidate && file.default_model_input {
                unsafe_sensitive_slice_paths.push(file.path.as_str());
            }
        }
    }
    if !unknown_slice_paths.is_empty() {
        unknown_slice_paths.sort();
        unknown_slice_paths.dedup();
        errors.push(format!(
            "V09: 인벤토리에 없는 슬라이스 경로: {}",
            unknown_slice_paths.join(", ")
        ));
    }
    if !unsafe_sensitive_slice_paths.is_empty() {
        unsafe_sensitive_slice_paths.sort();
        unsafe_sensitive_slice_paths.dedup();
        errors.push(format!(
            "V10: 민감 후보 기본 모델 입력 허용: {}",
            unsafe_sensitive_slice_paths.join(", ")
        ));
    }
    if !slice_flag_mismatch.is_empty() {
        slice_flag_mismatch.sort();
        slice_flag_mismatch.dedup();
        errors.push(format!(
            "V11: 슬라이스 승인 플래그 불일치: {}",
            slice_flag_mismatch.join(", ")
        ));
    }

    let mut unknown_dependency_manifests = data
        .dependencies
        .manifests
        .iter()
        .filter(|manifest| !inventory_files.contains(manifest.path.as_str()))
        .map(|manifest| manifest.path.as_str())
        .collect::<Vec<_>>();
    if !unknown_dependency_manifests.is_empty() {
        unknown_dependency_manifests.sort();
        unknown_dependency_manifests.dedup();
        errors.push(format!(
            "V12: 인벤토리에 없는 의존성 매니페스트 경로: {}",
            unknown_dependency_manifests.join(", ")
        ));
    }

    let mut metadata_mismatches = artifact_metadata(data)
        .into_iter()
        .filter(|(_, schema_version, run_id)| {
            *schema_version != SCHEMA_VERSION || *run_id != data.run_id
        })
        .map(|(name, _, _)| name)
        .collect::<Vec<_>>();
    if !metadata_mismatches.is_empty() {
        metadata_mismatches.sort();
        metadata_mismatches.dedup();
        errors.push(format!(
            "V13: 산출물 공통 메타데이터 불일치: {}",
            metadata_mismatches.join(", ")
        ));
    }

    if errors.is_empty() {
        let review_mismatches = review_summary_mismatches(data);
        if !review_mismatches.is_empty() {
            errors.push(format!(
                "V14: review.json 요약 불일치: {}",
                review_mismatches.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn artifact_metadata(data: &RunData) -> Vec<(&'static str, &str, &str)> {
    vec![
        (
            "source.json",
            &data.source.schema_version,
            &data.source.run_id,
        ),
        (
            "inventory.json",
            &data.inventory.schema_version,
            &data.inventory.run_id,
        ),
        (
            "coverage.json",
            &data.coverage.schema_version,
            &data.coverage.run_id,
        ),
        (
            "evidence.json",
            &data.evidence.schema_version,
            &data.evidence.run_id,
        ),
        (
            "findings.json",
            &data.findings.schema_version,
            &data.findings.run_id,
        ),
        (
            "dependencies.json",
            &data.dependencies.schema_version,
            &data.dependencies.run_id,
        ),
        (
            "sectors.json",
            &data.sectors.schema_version,
            &data.sectors.run_id,
        ),
        (
            "sensitive.json",
            &data.sensitive.schema_version,
            &data.sensitive.run_id,
        ),
        ("gates.json", &data.gates.schema_version, &data.gates.run_id),
        (
            "slices.json",
            &data.slices.schema_version,
            &data.slices.run_id,
        ),
        (
            "review.json",
            &data.review.schema_version,
            &data.review.run_id,
        ),
    ]
}

fn review_summary_mismatches(data: &RunData) -> Vec<&'static str> {
    let mut mismatches = Vec::new();
    let counts = &data.review.counts;

    if counts.findings_total != data.findings.findings.len() as u64 {
        mismatches.push("findings_total");
    }
    if counts.high_priority_findings
        != data
            .findings
            .findings
            .iter()
            .filter(|finding| finding.priority() == Priority::High)
            .count() as u64
    {
        mismatches.push("high_priority_findings");
    }
    if counts.medium_priority_findings
        != data
            .findings
            .findings
            .iter()
            .filter(|finding| finding.priority() == Priority::Medium)
            .count() as u64
    {
        mismatches.push("medium_priority_findings");
    }
    if counts.sensitive_candidates != data.gates.sensitive_candidates.len() as u64 {
        mismatches.push("sensitive_candidates");
    }
    if counts.automatic_execution_candidates
        != data.gates.automatic_execution_candidates.len() as u64
    {
        mismatches.push("automatic_execution_candidates");
    }
    if counts.execution_related_candidates != data.gates.execution_related_candidates.len() as u64 {
        mismatches.push("execution_related_candidates");
    }
    if counts.slices_total != data.slices.slices.len() as u64 {
        mismatches.push("slices_total");
    }
    if counts.slices_over_token_limit
        != data
            .slices
            .slices
            .iter()
            .filter(|slice| slice.over_token_limit)
            .count() as u64
    {
        mismatches.push("slices_over_token_limit");
    }

    let expected_excluded_paths = data
        .slices
        .slices
        .iter()
        .flat_map(|slice| slice.files.iter())
        .filter(|file| !file.default_model_input)
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let actual_excluded_paths = data
        .review
        .default_model_excluded_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_excluded_paths != expected_excluded_paths {
        mismatches.push("default_model_excluded_paths");
    }

    let expected_verdict = if data.gates.sensitive_raw_review.approval_required
        || data.gates.execution_review.approval_required
    {
        "approval-required"
    } else if !data.findings.findings.is_empty() {
        "review-required"
    } else {
        "no-findings-within-observed-scope"
    };
    if data.review.verdict != expected_verdict {
        mismatches.push("verdict");
    }

    mismatches
}

pub fn verify_outputs(out_dir: &Path) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let missing: Vec<&str> = ARTIFACTS
        .iter()
        .copied()
        .filter(|name| !out_dir.join(name).is_file())
        .collect();
    if !missing.is_empty() {
        errors.push(format!("V01: 산출물 파일 누락: {}", missing.join(", ")));
    }

    let report = fs::read_to_string(out_dir.join("report.md")).unwrap_or_default();
    if !report.contains(NO_EXEC_SENTENCE) {
        errors.push("V05: 무실행 문장 누락".into());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

const ARTIFACTS: [&str; 14] = [
    "run.json",
    "source.json",
    "inventory.json",
    "coverage.json",
    "evidence.json",
    "findings.json",
    "dependencies.json",
    "gates.json",
    "review.json",
    "sensitive.json",
    "slices.json",
    "report.md",
    "report.html",
    "sectors.json",
];
