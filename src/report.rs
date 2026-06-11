//! 사람용 리포트.
//! 마지막 무실행 문장은 model::NO_EXEC_SENTENCE 상수를 쓴다.

use crate::model::{GitInfo, Priority, RunData, NO_EXEC_SENTENCE};

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
