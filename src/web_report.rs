//! 실행별 HTML 리포트.
//!
//! 기존 RunData만 렌더링한다. 대상 저장소 파일을 새로 읽지 않는다.

use crate::model::{Priority, ReviewAction, RunData, SensitiveReviewMode, NO_EXEC_SENTENCE};

pub fn render(data: &RunData) -> String {
    let findings = if data.findings.findings.is_empty() {
        "<p class=\"empty\">발견사항 없음</p>".into()
    } else {
        let rows = data
            .findings
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(finding.id()),
                    priority_label(finding.priority()),
                    escape(finding.summary()),
                    escape(&finding.evidence_ids().join(", "))
                )
            })
            .collect::<String>();
        format!(
            "<table><thead><tr><th>번호</th><th>우선순위</th><th>요약</th><th>증거</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };

    let required_actions = required_actions_html(&data.review.required_actions);

    format!(
        r#"<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>git-scv 검사 리포트</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #172033;
      --muted: #64748b;
      --line: #d8e0ea;
      --accent: #0f766e;
      --warn: #b45309;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0 48px;
    }}
    header, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }}
    h1, h2 {{ margin: 0; letter-spacing: 0; }}
    h1 {{ font-size: 28px; }}
    h2 {{ font-size: 18px; margin-bottom: 14px; }}
    .meta, .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfdff;
    }}
    .label {{ color: var(--muted); font-size: 13px; }}
    .value {{ font-weight: 700; margin-top: 4px; overflow-wrap: anywhere; }}
    .verdict {{ color: var(--warn); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 700; }}
    ul {{ margin: 0; padding-left: 20px; }}
    li + li {{ margin-top: 8px; }}
    li span {{ color: var(--muted); margin-left: 8px; }}
    .empty {{ color: var(--muted); margin: 0; }}
    .note {{ color: var(--muted); margin: 10px 0 0; }}
    .noexec {{
      border-left: 4px solid var(--accent);
      padding-left: 12px;
      font-weight: 700;
    }}
    .stage {{
      border-left: 5px solid var(--warn);
      background: #fff7ed;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>git-scv 검사 리포트</h1>
      <p class="note">범위가 제한된 무실행 검토 출력입니다. 안전 보증이 아닙니다.</p>
      <div class="item stage">
        <div class="label">analysis stage</div>
        <div class="value">{analysis_stage}</div>
        <p class="note">{analysis_stage_label}</p>
        <p class="note">이 HTML은 정적 preflight 리포트입니다. LLM unit-analysis와 meta-synthesis 완료 보고서가 아닙니다.</p>
      </div>
      <div class="meta">
        <div class="item"><div class="label">실행 번호</div><div class="value">{run_id}</div></div>
        <div class="item"><div class="label">도구</div><div class="value">git-scv {version}</div></div>
        <div class="item"><div class="label">시작</div><div class="value">{started}</div></div>
        <div class="item"><div class="label">종료</div><div class="value">{finished}</div></div>
      </div>
    </header>
    <section>
      <h2>기계 요약</h2>
      <div class="grid">
        <div class="item"><div class="label">판정</div><div class="value verdict">{verdict}</div></div>
        <div class="item"><div class="label">발견사항</div><div class="value">{findings_total}</div></div>
        <div class="item"><div class="label">민감 후보</div><div class="value">{sensitive_count}</div></div>
        <div class="item"><div class="label">깊은 분석 후보</div><div class="value">{deep_analysis_candidates}</div></div>
        <div class="item"><div class="label">슬라이스</div><div class="value">{slice_count}</div></div>
        <div class="item"><div class="label">의존성 이름</div><div class="value">{dependency_count}</div></div>
      </div>
    </section>
    <section>
      <h2>민감 후보 처리</h2>
      <div class="grid">
        <div class="item"><div class="label">모드</div><div class="value">{sensitive_mode}</div></div>
        <div class="item"><div class="label">후보</div><div class="value">{sensitive_candidates}</div></div>
        <div class="item"><div class="label">원문 승인 경로</div><div class="value">{approved_paths}</div></div>
        <div class="item"><div class="label">승인 ack 확인</div><div class="value">1차 {review_ack} / 2차 {raw_ack}</div></div>
      </div>
      <p class="note">{sensitive_note}</p>
    </section>
    <section>
      <h2>승인 게이트</h2>
      <ul>{required_actions}</ul>
    </section>
    <section>
      <h2>Architecture Visualization</h2>
      <div class="grid">
        <div class="item"><div class="label">기본 시각화</div><div class="value">architecture.html</div></div>
        <div class="item"><div class="label">주요 view</div><div class="value">overview, execution-scenarios, security-gates, synthesis</div></div>
        <div class="item"><div class="label">raw target content</div><div class="value">not included</div></div>
        <div class="item"><div class="label">safe claim made</div><div class="value">false</div></div>
      </div>
      <p class="note">architecture.html은 Git-SCV가 생성한 정적 viewer이며 target repository HTML/JS를 실행하지 않습니다.</p>
    </section>
    <section>
      <h2>발견사항</h2>
      {findings}
    </section>
    <section>
      <h2>무실행 확인</h2>
      <p class="noexec">{no_exec}</p>
    </section>
  </main>
</body>
</html>
"#,
        run_id = escape(&data.run_id),
        analysis_stage = data.analysis_state.analysis_stage.as_str(),
        analysis_stage_label = escape(data.analysis_state.analysis_stage.user_badge()),
        version = env!("CARGO_PKG_VERSION"),
        started = escape(&data.started_at),
        finished = escape(&data.finished_at),
        verdict = escape(&data.review.verdict),
        findings_total = data.review.counts.findings_total,
        sensitive_count = data.review.counts.sensitive_candidates,
        deep_analysis_candidates = data.review.counts.deep_analysis_candidates,
        slice_count = data.review.counts.slices_total,
        dependency_count = data
            .dependencies
            .manifests
            .iter()
            .map(|manifest| manifest.dependencies.len())
            .sum::<usize>(),
        sensitive_mode = sensitive_mode_label(data.sensitive.mode),
        sensitive_candidates = data.sensitive.candidates.len(),
        approved_paths = data.sensitive.approved_paths.len(),
        review_ack = yes_no(data.sensitive.review_ack_confirmed),
        raw_ack = yes_no(data.sensitive.raw_ack_confirmed),
        sensitive_note = escape(&data.sensitive.note),
        required_actions = required_actions,
        findings = findings,
        no_exec = escape(NO_EXEC_SENTENCE),
    )
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
        SensitiveReviewMode::Exclude => "exclude",
        SensitiveReviewMode::RedactedSummary => "redacted-summary",
        SensitiveReviewMode::ApprovedRaw => "approved-raw",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "예"
    } else {
        "아니오"
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn required_actions_html(actions: &[ReviewAction]) -> String {
    let items = actions
        .iter()
        .filter(|action| action.required)
        .map(|action| {
            let acknowledgements = if action.acknowledgements.is_empty() {
                String::new()
            } else {
                format!(
                    "<span>ack {}</span>",
                    escape(&action.acknowledgements.join(", "))
                )
            };
            format!(
                "<li><strong>{}</strong><span>{}개 경로</span>{acknowledgements}</li>",
                escape(&action.id),
                action.paths.len()
            )
        })
        .collect::<String>();

    if items.is_empty() {
        "<li><strong>필수 액션 없음</strong><span>현재 관찰 범위 기준</span></li>".into()
    } else {
        items
    }
}

#[cfg(test)]
mod tests {
    use super::required_actions_html;
    use crate::model::ReviewAction;

    #[test]
    fn required_actions_html_lists_required_actions_and_acknowledgements() {
        let html = required_actions_html(&[
            action(
                "sensitive-raw-review",
                true,
                vec![".env.sh"],
                vec![
                    "review-sensitive-candidates",
                    "include-approved-sensitive-raw-in-diagnostic-input",
                ],
            ),
            action(
                "execution-model-input-review",
                true,
                vec!["build.rs"],
                vec![],
            ),
            action("not-required", false, vec!["ignored"], vec!["ignored-ack"]),
        ]);

        assert!(html.contains("<strong>sensitive-raw-review</strong>"));
        assert!(html.contains("<span>1개 경로</span>"));
        assert!(html.contains(
            "ack review-sensitive-candidates, include-approved-sensitive-raw-in-diagnostic-input"
        ));
        assert!(html.contains("<strong>execution-model-input-review</strong>"));
        assert!(!html.contains("not-required"));
        assert!(!html.contains("ignored-ack"));
    }

    #[test]
    fn required_actions_html_reports_no_required_actions() {
        let html = required_actions_html(&[action(
            "sensitive-raw-review",
            false,
            vec![".env"],
            vec!["review-sensitive-candidates"],
        )]);

        assert_eq!(
            html,
            "<li><strong>필수 액션 없음</strong><span>현재 관찰 범위 기준</span></li>"
        );
    }

    fn action(
        id: &str,
        required: bool,
        paths: Vec<&str>,
        acknowledgements: Vec<&str>,
    ) -> ReviewAction {
        ReviewAction {
            id: id.into(),
            required,
            reason: String::new(),
            paths: paths.into_iter().map(str::to_string).collect(),
            acknowledgements: acknowledgements.into_iter().map(str::to_string).collect(),
        }
    }
}
