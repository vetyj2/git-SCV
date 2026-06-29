//! 검증 관문.
//!
//! validate: 쓰기 전 메모리 검증 (V02–V24)
//! verify_outputs: 쓰기 후 디스크 검증 (V01, V05) — 이 함수만 IO 예외다
//! (architecture.md 1절). 실패 문자열은 사양의 표 그대로 만든다.

use crate::model::{
    EvidenceKind, Priority, ReviewAction, RunData, LOW_CONFIDENCE_SENTENCE, NO_EXEC_SENTENCE,
    SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
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
        .execution_model_input_review
        .paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if prompt_sensitive_paths != gate_sensitive_paths || prompt_execution_paths != execution_paths {
        errors.push("V08: 승인 프롬프트 경로 불일치".into());
    }

    let inventory_paths = data
        .inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut unknown_evidence_paths = data
        .evidence
        .evidence
        .iter()
        .filter(|item| !inventory_paths.contains(item.path.as_str()))
        .map(|item| item.path.as_str())
        .collect::<Vec<_>>();
    if !unknown_evidence_paths.is_empty() {
        unknown_evidence_paths.sort();
        unknown_evidence_paths.dedup();
        errors.push(format!(
            "V17: 인벤토리에 없는 증거 경로: {}",
            unknown_evidence_paths.join(", ")
        ));
    }

    let mut malformed_evidence = data
        .evidence
        .evidence
        .iter()
        .filter(|item| evidence_shape_error(item))
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>();
    if !malformed_evidence.is_empty() {
        malformed_evidence.sort();
        malformed_evidence.dedup();
        errors.push(format!(
            "V18: 증거 형태 불일치: {}",
            malformed_evidence.join(", ")
        ));
    }

    let inventory_files = data
        .inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == crate::model::EntryKind::File)
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let inventory_file_entries = data
        .inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == crate::model::EntryKind::File)
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut unknown_slice_paths = Vec::new();
    let mut unsafe_sensitive_slice_paths = Vec::new();
    let mut unsafe_execution_slice_paths = Vec::new();
    let mut slice_flag_mismatch = Vec::new();
    let mut slice_language_mismatch = Vec::new();
    let mut duplicate_slice_paths = Vec::new();
    let mut slice_seen_paths = BTreeSet::new();
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
            if !slice_seen_paths.insert(file.path.as_str()) {
                duplicate_slice_paths.push(file.path.as_str());
            }
            if !inventory_files.contains(file.path.as_str()) {
                unknown_slice_paths.push(file.path.as_str());
            } else if let Some(entry) = inventory_file_entries.get(file.path.as_str()) {
                let expected_language = crate::language::language_hint(entry);
                let expected_deep = crate::language::is_deep_analysis_candidate(expected_language);
                if file.language_hint.as_deref() != expected_language
                    || file.deep_analysis_candidate != expected_deep
                {
                    slice_language_mismatch.push(file.path.as_str());
                }
            }
            if file.sensitive_candidate && file.default_model_input {
                unsafe_sensitive_slice_paths.push(file.path.as_str());
            }
            if (file.automatic_execution_candidate || file.execution_related_candidate)
                && file.default_model_input
            {
                unsafe_execution_slice_paths.push(file.path.as_str());
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
    if !unsafe_execution_slice_paths.is_empty() {
        unsafe_execution_slice_paths.sort();
        unsafe_execution_slice_paths.dedup();
        errors.push(format!(
            "V19: 실행 후보 기본 모델 입력 허용: {}",
            unsafe_execution_slice_paths.join(", ")
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
    if !slice_language_mismatch.is_empty() {
        slice_language_mismatch.sort();
        slice_language_mismatch.dedup();
        errors.push(format!(
            "V20: 슬라이스 언어 힌트 불일치: {}",
            slice_language_mismatch.join(", ")
        ));
    }
    if !duplicate_slice_paths.is_empty() {
        duplicate_slice_paths.sort();
        duplicate_slice_paths.dedup();
        errors.push(format!(
            "V23: 중복 슬라이스 파일 경로: {}",
            duplicate_slice_paths.join(", ")
        ));
    }

    let mut sector_read_order_unknown_paths = Vec::new();
    let mut sector_read_order_duplicates = Vec::new();
    let mut sector_seen = BTreeSet::new();
    for path in &data.sectors.suggested_read_order {
        if !inventory_files.contains(path.as_str()) {
            sector_read_order_unknown_paths.push(path.as_str());
        }
        if !sector_seen.insert(path.as_str()) {
            sector_read_order_duplicates.push(path.as_str());
        }
    }
    if !sector_read_order_unknown_paths.is_empty() || !sector_read_order_duplicates.is_empty() {
        sector_read_order_unknown_paths.sort();
        sector_read_order_unknown_paths.dedup();
        sector_read_order_duplicates.sort();
        sector_read_order_duplicates.dedup();
        let mut parts = Vec::new();
        if !sector_read_order_unknown_paths.is_empty() {
            parts.push(format!(
                "unknown={}",
                sector_read_order_unknown_paths.join(", ")
            ));
        }
        if !sector_read_order_duplicates.is_empty() {
            parts.push(format!(
                "duplicate={}",
                sector_read_order_duplicates.join(", ")
            ));
        }
        errors.push(format!("V21: 읽기 순서 경로 불일치: {}", parts.join("; ")));
    }

    if data.slices.policy.source_order == "sectors.suggested_read_order" {
        let slice_order = data
            .slices
            .slices
            .iter()
            .flat_map(|slice| slice.files.iter())
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        let mut order_mismatch = Vec::new();
        for (index, expected) in data.sectors.suggested_read_order.iter().enumerate() {
            match slice_order.get(index) {
                Some(actual) if actual == expected => {}
                Some(actual) => order_mismatch.push(format!("{expected}!={actual}")),
                None => order_mismatch.push(format!("{expected}=missing")),
            }
        }
        if !order_mismatch.is_empty() {
            errors.push(format!(
                "V22: 슬라이스 읽기 순서 불일치: {}",
                order_mismatch.join(", ")
            ));
        }
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

    let mut unknown_gate_paths = data
        .gates
        .sensitive_candidates
        .iter()
        .chain(data.gates.automatic_execution_candidates.iter())
        .chain(data.gates.execution_related_candidates.iter())
        .filter(|item| !inventory_paths.contains(item.path.as_str()))
        .map(|item| item.path.as_str())
        .collect::<Vec<_>>();
    if !unknown_gate_paths.is_empty() {
        unknown_gate_paths.sort();
        unknown_gate_paths.dedup();
        errors.push(format!(
            "V16: 인벤토리에 없는 게이트 후보 경로: {}",
            unknown_gate_paths.join(", ")
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
        let action_mismatches = review_action_mismatches(data);
        if !action_mismatches.is_empty() {
            errors.push(format!(
                "V15: review.json 필수 액션 불일치: {}",
                action_mismatches.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        let security_mismatches = security_summary_mismatches(data);
        if !security_mismatches.is_empty() {
            errors.push(format!(
                "V24: security.json 요약 불일치: {}",
                security_mismatches.join(", ")
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn evidence_shape_error(item: &crate::model::Evidence) -> bool {
    let invalid_lines = match item.kind {
        EvidenceKind::ContentLine => match item.lines {
            Some(lines) => lines.start == 0 || lines.end < lines.start,
            None => true,
        },
        EvidenceKind::FilePresence | EvidenceKind::SymlinkRecord | EvidenceKind::SecretName => {
            item.lines.is_some()
        }
    };
    let invalid_json_pointer = item.kind == EvidenceKind::ContentLine
        && item.json_pointer.is_none()
        || item.kind != EvidenceKind::ContentLine && item.json_pointer.is_some();
    let invalid_redacted_excerpt = match item.kind {
        EvidenceKind::ContentLine => item.redacted_excerpt.is_none(),
        EvidenceKind::FilePresence | EvidenceKind::SymlinkRecord | EvidenceKind::SecretName => {
            item.redacted_excerpt.is_some()
        }
    };
    let invalid_raw_storage = item.value_stored || item.raw_excerpt_stored;
    invalid_lines || invalid_json_pointer || invalid_redacted_excerpt || invalid_raw_storage
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
        (
            "security.json",
            &data.security.schema_version,
            &data.security.run_id,
        ),
        (
            "connection_graph.json",
            &data.connection_graph.schema_version,
            &data.connection_graph.run_id,
        ),
        (
            "analysis_plan.json",
            &data.analysis_plan.schema_version,
            &data.analysis_plan.run_id,
        ),
        (
            "cross_unit_analysis.json",
            &data.cross_unit_analysis.schema_version,
            &data.cross_unit_analysis.run_id,
        ),
        (
            "synthesis.json",
            &data.synthesis.schema_version,
            &data.synthesis.run_id,
        ),
        (
            "followup_plan.json",
            &data.followup_plan.schema_version,
            &data.followup_plan.run_id,
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
    if counts.deep_analysis_candidates
        != data
            .slices
            .slices
            .iter()
            .flat_map(|slice| slice.files.iter())
            .filter(|file| file.deep_analysis_candidate)
            .count() as u64
    {
        mismatches.push("deep_analysis_candidates");
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

    let unsupported_surface = coverage_has_insufficient_surface(&data.coverage);
    let expected_verdict = if !data.coverage.limit_reason_codes.is_empty() || unsupported_surface {
        "insufficient-coverage"
    } else if data.gates.sensitive_raw_review.approval_required
        || data.gates.execution_model_input_review.approval_required
        || data.gates.execution_command_review.approval_required
    {
        "approval-required"
    } else if !data.findings.findings.is_empty() {
        "review-required"
    } else {
        "no-blocker-observed"
    };
    if data.review.verdict != expected_verdict || !allowed_verdict(&data.review.verdict) {
        mismatches.push("verdict");
    }
    if data.review.safe_claim_made {
        mismatches.push("safe_claim_made");
    }
    if data.review.may_user_run_install {
        mismatches.push("may_user_run_install");
    }
    if !data.review.may_agent_request_run_approval {
        mismatches.push("may_agent_request_run_approval");
    }
    if data.review.may_agent_run_without_user {
        mismatches.push("may_agent_run_without_user");
    }
    let actual_reason_codes = data
        .review
        .reason_codes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_reason_codes = expected_reason_codes(data);
    if actual_reason_codes != expected_reason_codes {
        mismatches.push("reason_codes");
    }

    mismatches
}

fn allowed_verdict(verdict: &str) -> bool {
    matches!(
        verdict,
        "blocked-pending-review"
            | "approval-required"
            | "review-required"
            | "no-blocker-observed"
            | "insufficient-coverage"
            | "stale-source"
            | "failed"
    )
}

fn expected_reason_codes(data: &RunData) -> BTreeSet<&str> {
    let mut codes = BTreeSet::new();
    if !data.coverage.limit_reason_codes.is_empty() {
        codes.extend(data.coverage.limit_reason_codes.iter().map(String::as_str));
    }
    if coverage_has_insufficient_surface(&data.coverage) {
        codes.insert("unsupported-surface-name-detected");
    }
    if data.gates.sensitive_raw_review.approval_required {
        codes.insert("sensitive-candidates-present");
    }
    if data.gates.execution_model_input_review.approval_required
        || data.gates.execution_command_review.approval_required
    {
        codes.insert("execution-candidates-present");
    }
    if data
        .slices
        .slices
        .iter()
        .any(|slice| slice.over_token_limit)
    {
        codes.insert("slice-token-limit-exceeded");
    }
    if !data.findings.findings.is_empty() {
        codes.insert("findings-present");
    }
    if data
        .source
        .git
        .as_ref()
        .is_some_and(|git| git.is_repo && git.dirty.is_none())
    {
        codes.insert("source-dirty-unknown");
    }
    if codes.is_empty() {
        codes.insert("observed-scope-no-blocker");
    }
    codes
}

fn coverage_has_insufficient_surface(coverage: &crate::model::CoverageArtifact) -> bool {
    coverage
        .capabilities
        .iter()
        .any(|capability| capability.verdict_effect.as_deref() == Some("insufficient-coverage"))
}

fn review_action_mismatches(data: &RunData) -> Vec<&'static str> {
    let mut mismatches = Vec::new();
    let mut actions: BTreeMap<&str, &ReviewAction> = BTreeMap::new();
    let mut duplicate_id = false;
    for action in &data.review.required_actions {
        if actions.insert(action.id.as_str(), action).is_some() {
            duplicate_id = true;
        }
    }
    if duplicate_id || actions.len() != 4 {
        mismatches.push("required_action_ids");
    }

    check_action(
        &mut mismatches,
        &actions,
        "sensitive-raw-review",
        data.gates.sensitive_raw_review.approval_required,
        &data.gates.sensitive_raw_review.paths,
        &data.gates.sensitive_raw_review.acknowledgements,
    );
    check_action(
        &mut mismatches,
        &actions,
        "execution-model-input-review",
        data.gates.execution_model_input_review.approval_required,
        &data.gates.execution_model_input_review.paths,
        &data.gates.execution_model_input_review.acknowledgements,
    );
    check_action(
        &mut mismatches,
        &actions,
        "execution-command-review",
        data.gates.execution_command_review.approval_required,
        &[],
        &data.gates.execution_command_review.acknowledgements,
    );
    check_action(
        &mut mismatches,
        &actions,
        "oversized-slice-review",
        data.slices
            .slices
            .iter()
            .any(|slice| slice.over_token_limit),
        &[],
        &[],
    );

    mismatches.sort();
    mismatches.dedup();
    mismatches
}

fn check_action(
    mismatches: &mut Vec<&'static str>,
    actions: &BTreeMap<&str, &ReviewAction>,
    id: &'static str,
    expected_required: bool,
    expected_paths: &[String],
    expected_acknowledgements: &[String],
) {
    let Some(action) = actions.get(id) else {
        mismatches.push(id);
        return;
    };
    let actual_paths = action
        .paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_paths = expected_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual_acknowledgements = action
        .acknowledgements
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_acknowledgements = expected_acknowledgements
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if action.required != expected_required
        || actual_paths != expected_paths
        || actual_acknowledgements != expected_acknowledgements
    {
        mismatches.push(id);
    }
}

fn security_summary_mismatches(data: &RunData) -> Vec<&'static str> {
    let mut mismatches = Vec::new();

    if data.security.verdict != data.review.verdict {
        mismatches.push("verdict");
    }
    if data.security.safe_claim_made != data.review.safe_claim_made {
        mismatches.push("safe_claim_made");
    }
    if data.security.may_user_run_install != data.review.may_user_run_install {
        mismatches.push("may_user_run_install");
    }
    if data.security.may_agent_request_run_approval != data.review.may_agent_request_run_approval {
        mismatches.push("may_agent_request_run_approval");
    }
    if data.security.may_agent_run_without_user != data.review.may_agent_run_without_user {
        mismatches.push("may_agent_run_without_user");
    }
    if data.security.reason_codes != data.review.reason_codes {
        mismatches.push("reason_codes");
    }
    if data.security.action_required
        != data
            .review
            .required_actions
            .iter()
            .any(|action| action.required)
    {
        mismatches.push("action_required");
    }
    if data.security.no_exec != NO_EXEC_SENTENCE {
        mismatches.push("no_exec");
    }
    if data.security.counts != data.review.counts {
        mismatches.push("counts");
    }
    if data.security.required_actions != data.review.required_actions {
        mismatches.push("required_actions");
    }
    if data.security.default_model_excluded_paths != data.review.default_model_excluded_paths {
        mismatches.push("default_model_excluded_paths");
    }
    if data.security.limitations != data.findings.limitations {
        mismatches.push("limitations");
    }

    for name in [
        "review.json",
        "findings.json",
        "evidence.json",
        "gates.json",
        "slices.json",
        "sensitive.json",
    ] {
        if !data.security.references.iter().any(|item| item == name) {
            mismatches.push("references");
            break;
        }
    }

    mismatches.sort();
    mismatches.dedup();
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

    let leak_errors = artifact_leak_errors(out_dir);
    if !leak_errors.is_empty() {
        errors.push(format!("V25: 산출물 누출 의심: {}", leak_errors.join(", ")));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn artifact_leak_errors(out_dir: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    for name in ARTIFACTS {
        let path = out_dir.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        errors.extend(scan_artifact_text(name, &text));
    }
    errors.sort();
    errors.dedup();
    errors
}

fn scan_artifact_text(name: &str, text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let mut errors = Vec::new();

    for marker in [
        "git_scv_fake_token_do_not_use",
        "git_scv_fake_bearer_do_not_use",
        "ghp_fake",
        "github_pat_",
    ] {
        if lower.contains(marker) {
            errors.push(format!("{name}:fake-secret-marker"));
        }
    }
    for raw_flag in [
        "\"raw_args_stored\":true",
        "\"raw_excerpt_stored\":true",
        "\"raw_content_stored\":true",
        "\"value_stored\":true",
    ] {
        if compact.contains(raw_flag) {
            errors.push(format!("{name}:raw-storage-flag"));
        }
    }
    if lower.contains("authorization: bearer") || lower.contains("bearer abc") {
        errors.push(format!("{name}:authorization-like"));
    }
    if lower.contains("token=") || lower.contains("access_token=") || lower.contains("auth_token=")
    {
        errors.push(format!("{name}:token-assignment"));
    }
    if lower.contains("\"postinstall\": \"") || lower.contains("\\\"postinstall\\\": \\\"") {
        errors.push(format!("{name}:raw-lifecycle-script"));
    }
    if contains_url_query_or_fragment(text) {
        errors.push(format!("{name}:url-query-or-fragment"));
    }

    errors
}

fn contains_url_query_or_fragment(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        let Some(scheme_index) = token.find("://") else {
            return false;
        };
        let before_scheme = &token[..scheme_index];
        if before_scheme
            .chars()
            .rev()
            .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
            .count()
            == 0
        {
            return false;
        }
        let urlish = &token[scheme_index + "://".len()..];
        urlish.contains('?') || urlish.contains('#')
    })
}

const ARTIFACTS: [&str; 23] = [
    "artifact_manifest.json",
    "brief.json",
    "brief.md",
    "run.json",
    "source.json",
    "inventory.json",
    "coverage.json",
    "evidence.json",
    "findings.json",
    "dependencies.json",
    "sectors.json",
    "sensitive.json",
    "gates.json",
    "slices.json",
    "review.json",
    "security.json",
    "connection_graph.json",
    "analysis_plan.json",
    "cross_unit_analysis.json",
    "synthesis.json",
    "followup_plan.json",
    "report.md",
    "report.html",
];
