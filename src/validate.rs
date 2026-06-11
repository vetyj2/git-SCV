//! 검증 관문.
//!
//! validate: 쓰기 전 메모리 검증 (V02, V03, V04, V06)
//! verify_outputs: 쓰기 후 디스크 검증 (V01, V05) — 이 함수만 IO 예외다
//! (architecture.md 1절). 실패 문자열은 사양의 표 그대로 만든다.

use crate::model::{RunData, LOW_CONFIDENCE_SENTENCE, NO_EXEC_SENTENCE};
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

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
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

const ARTIFACTS: [&str; 9] = [
    "run.json",
    "source.json",
    "inventory.json",
    "coverage.json",
    "evidence.json",
    "findings.json",
    "sensitive.json",
    "report.md",
    "sectors.json",
];
