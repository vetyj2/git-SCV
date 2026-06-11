//! 사람용 리포트.
//! 마지막 무실행 문장은 model::NO_EXEC_SENTENCE 상수를 쓴다.

use crate::model::{GitInfo, Priority, RunData, SensitiveReviewMode, NO_EXEC_SENTENCE};

pub fn render(data: &RunData) -> String {
    let findings = if data.findings.findings.is_empty() {
        "발견사항 없음\n".into()
    } else {
        let mut table =
            String::from("| 번호 | 우선순위 | 요약 | 증거 |\n| --- | --- | --- | --- |\n");
        for finding in &data.findings.findings {
            table.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                finding.id(),
                priority_label(finding.priority()),
                finding.summary(),
                finding.evidence_ids().join(", ")
            ));
        }
        table
    };

    let limitations = data
        .findings
        .limitations
        .iter()
        .map(|item| format!("- {item}\n"))
        .collect::<String>();

    format!(
        "# git-scv 검사 리포트\n\n\
- 실행 번호: {run_id}\n\
- 도구: git-scv {version}\n\
- 시작: {started_at} / 종료: {finished_at}\n\n\
## 원본\n\n\
- 입력 경로: {input}\n\
- 해석된 경로: {resolved}\n\
- 깃 정보: {git}\n\
- 스냅샷: 없음\n\n\
## 범위\n\n\
- 발견 항목: {discovered} / 나열: {listed} / 건너뜀: {skipped}\n\
- 내용을 읽은 파일: {files_read}개, {bytes_read_total}바이트\n\
- 정책: 무시 규칙 미적용, 심볼릭 링크 미추적, 탐색 한도 없음\n\n\
## 민감 후보 처리\n\n\
- 모드: {sensitive_mode}\n\
- 후보: {sensitive_candidates}개 / 원문 승인 경로: {approved_paths}개\n\
- 원문 저장: 없음\n\
- 메모: {sensitive_note}\n\n\
## 승인 게이트\n\n\
- 민감 후보 원문 승인 필요: {sensitive_gate}\n\
- 실행 승인 필요: {execution_gate}\n\
- 자동 실행 후보: {auto_exec_count}개 / 실행 관련 후보: {execution_related_count}개\n\n\
## 읽기 슬라이스\n\n\
- 슬라이스: {slice_count}개\n\
- 슬라이스당 최대 추정 토큰: {slice_limit}\n\
- 한도 초과 단일 파일 슬라이스: {over_limit_slices}개\n\
- 기본 모델 입력 정책: 민감 후보 제외\n\n\
## 발견사항\n\n\
{findings}\n\
## 한계\n\n\
{limitations}\n\
## 무실행 확인\n\n\
{NO_EXEC_SENTENCE}\n",
        run_id = data.run_id.as_str(),
        version = env!("CARGO_PKG_VERSION"),
        started_at = data.started_at.as_str(),
        finished_at = data.finished_at.as_str(),
        input = data.source.input.raw.as_str(),
        resolved = data.source.resolved_path.as_str(),
        git = git_summary(data.source.git.as_ref()),
        discovered = data.inventory.totals.discovered,
        listed = data.inventory.totals.listed,
        skipped = data.inventory.totals.skipped,
        files_read = data.coverage.files_read,
        bytes_read_total = data.coverage.bytes_read_total,
        sensitive_mode = sensitive_mode_label(data.sensitive.mode),
        sensitive_candidates = data.sensitive.candidates.len(),
        approved_paths = data.sensitive.approved_paths.len(),
        sensitive_note = data.sensitive.note.as_str(),
        sensitive_gate = yes_no(data.gates.sensitive_raw_review.approval_required),
        execution_gate = yes_no(data.gates.execution_review.approval_required),
        auto_exec_count = data.gates.automatic_execution_candidates.len(),
        execution_related_count = data.gates.execution_related_candidates.len(),
        slice_count = data.slices.slices.len(),
        slice_limit = data.slices.policy.max_estimated_tokens_per_slice,
        over_limit_slices = data
            .slices
            .slices
            .iter()
            .filter(|slice| slice.over_token_limit)
            .count(),
        findings = findings,
        limitations = limitations,
    )
}

fn git_summary(git: Option<&GitInfo>) -> String {
    let Some(git) = git else {
        return "깃 정보 없음".into();
    };
    let branch = git
        .branch
        .as_deref()
        .map(|branch| format!("가지 {branch}"))
        .unwrap_or_else(|| "가지 (분리 HEAD)".into());
    let commit = git
        .commit
        .as_deref()
        .map(|commit| commit.chars().take(12).collect::<String>())
        .unwrap_or_else(|| "없음".into());
    let dirty = match git.dirty {
        Some(true) => "있음",
        Some(false) => "없음",
        None => "확인 안 됨",
    };
    format!("{branch}, 커밋 {commit}, 미커밋 변경 {dirty}")
}

fn priority_label(priority: Priority) -> &'static str {
    match priority {
        Priority::Info => "정보",
        Priority::Low => "낮음",
        Priority::Medium => "중간",
        Priority::High => "높음",
    }
}

fn sensitive_mode_label(mode: SensitiveReviewMode) -> &'static str {
    match mode {
        SensitiveReviewMode::Exclude => "제외",
        SensitiveReviewMode::RedactedSummary => "가린 요약",
        SensitiveReviewMode::ApprovedRaw => "승인 원문",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "예"
    } else {
        "아니오"
    }
}
