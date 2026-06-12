//! 실행별 HTML 리포트.
//!
//! 기존 RunData만 렌더링한다. 대상 저장소 파일을 새로 읽지 않는다.

use crate::model::{Priority, RunData, NO_EXEC_SENTENCE};

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

    let required_actions = data
        .review
        .required_actions
        .iter()
        .filter(|action| action.required)
        .map(|action| {
            format!(
                "<li><strong>{}</strong><span>{}개 경로</span></li>",
                escape(&action.id),
                action.paths.len()
            )
        })
        .collect::<String>();
    let required_actions = if required_actions.is_empty() {
        "<li><strong>필수 액션 없음</strong><span>현재 관찰 범위 기준</span></li>".into()
    } else {
        required_actions
    };

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
  </style>
</head>
<body>
  <main>
    <header>
      <h1>git-scv 검사 리포트</h1>
      <p class="note">범위가 제한된 무실행 검토 출력입니다. 안전 보증이 아닙니다.</p>
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
        <div class="item"><div class="label">슬라이스</div><div class="value">{slice_count}</div></div>
        <div class="item"><div class="label">의존성 이름</div><div class="value">{dependency_count}</div></div>
      </div>
    </section>
    <section>
      <h2>승인 게이트</h2>
      <ul>{required_actions}</ul>
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
        version = env!("CARGO_PKG_VERSION"),
        started = escape(&data.started_at),
        finished = escape(&data.finished_at),
        verdict = escape(&data.review.verdict),
        findings_total = data.review.counts.findings_total,
        sensitive_count = data.review.counts.sensitive_candidates,
        slice_count = data.review.counts.slices_total,
        dependency_count = data
            .dependencies
            .manifests
            .iter()
            .map(|manifest| manifest.dependencies.len())
            .sum::<usize>(),
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

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
