# 사양 0900 — 산출물, 리포트, 섹터, 검증 관문

대상 모듈: `src/artifacts.rs`(0900), `src/report.rs`(0910),
`src/dependencies.rs`(0985), `src/sectors.rs`(0951),
`src/sensitive.rs`(0961), `src/gates.rs`(0962),
`src/slices.rs`(0971), `src/review.rs`(0981, 0987),
`src/graph.rs`, `src/visualization.rs`, `src/synthesis.rs`,
`src/unit_analysis.rs`,
`src/web_report.rs`(0991), `src/validate.rs`(0800)
관련 요구사항: 0801–0806, 0901–0909, 0951–0993, 1403A, 1406, 1429

## 1. 공통 규칙

- inspect 산출물은 `artifact_manifest.json`, `brief.json`, `brief.md`,
  `run.json`, `source.json`, `inventory.json`, `coverage.json`,
  `evidence.json`, `findings.json`, `dependencies.json`, `sectors.json`,
  `sensitive.json`, `gates.json`, `gate_decisions.json`, `slices.json`,
  `static_preflight_summary.json`, `sub_slices.json`, `sub_slices.jsonl`,
  `analysis_inputs.json`, `analysis_inputs.jsonl`, `analysis_state.json`,
  `analysis_events.jsonl`, `llm_backend.json`, `source_acquisition.json`,
  `gpt_work_order.json`,
  `gpt_work_order.md`, `analysis_jobs.jsonl`,
  `codex_invocation_receipt.jsonl`, `analysis_followup_jobs.jsonl`,
  `work_order_binding.json`,
  `review.json`, `security.json`, `supported_surfaces.json`,
  `connection_graph.json`, `reachability_scenarios.json`,
  `architecture_map.json`, `relation_map.json`, `source_landmarks.json`,
  `visualization_index.json`, `analysis_plan.json`, `analysis_map.json`,
  `cross_unit_analysis.json`, `synthesis.json`, `followup_plan.json`,
  `report.md`, `report.html`, `architecture.html`을 포함한다. agent receipt는
  `git-scv receipt create` 뒤 `agent_receipt.json`으로 추가된다.
- `git-scv scan --worker <backend>`는 inspect 산출물 위에
  `worker_backend.json`을 추가할 수 있다. 이 artifact는 OAuth/token 파일을
  저장하거나 참조하지 않고 worker CLI readiness와
  `target_repo_commands_executed:false`를 기록한다.
- v0.3은 artifact-contract-v2 release다. 모든 JSON artifact는
  `artifact_kind`, `contract_version`, `producer`, `min_reader_version`을
  포함한다. 기존 core artifact 중 일부는 내부 payload 스키마
  `"schema_version": "1"`을 유지하지만, `artifact_manifest`, `brief`,
  `agent_receipt` 등 v2 계약 artifact는 `"schema_version": "2"`를 가진다.
  v0.2 artifact는 migration하지 않고 재검사를 요구한다.
- JSON은 `serde_json::to_string_pretty`(2칸 들여쓰기)로 쓰고 끝에 줄바꿈
  하나를 붙인다.
- 모든 경로는 저장소 루트 기준 상대 경로, `/` 구분자. 모든 목록은 경로
  바이트 사전순(이미 정렬된 입력을 그대로 직렬화).
- 파일 쓰기 직전마다 `safety::assert_inside(out_root, target)` 호출(1105).
- 쓰기 순서 고정: source → inventory → coverage → evidence → findings →
  dependencies → sectors → sensitive → gates → gate_decisions → slices →
  static_preflight_summary → sub_slices → analysis_inputs → analysis_state →
  llm_backend → gpt_work_order → gpt_work_order.md → analysis_jobs →
  codex_invocation_receipt → review → security → supported_surfaces → connection_graph →
  reachability_scenarios → architecture_map → relation_map →
  source_landmarks → visualization_index → analysis_plan →
  analysis_map → cross_unit_analysis → synthesis → followup_plan →
  report.md → report.html → architecture.html → run.json →
  artifact_manifest.json → work_order_binding.json → brief.json/brief.md →
  디스크 검증.

## 2. 스키마 (필드 전부 — 추가·생략 금지)

### run.json (0902)

```json
{
  "schema_version": "1",
  "run_id": "scv-20260612T120003Z",
  "tool": { "name": "git-scv", "version": "0.3.3" },
  "command": {
    "program": "git-scv",
    "subcommand": "inspect",
    "args_redacted": ["<path>", "--out", "<path>"],
    "raw_args_stored": false
  },
  "started_at": "2026-06-12T12:00:03Z",
  "finished_at": "2026-06-12T12:00:05Z",
  "status": "success",
  "stages": [
    { "name": "source", "status": "ok", "error": null }
  ],
  "exit_code": 0
}
```

- `tool.version`은 `env!("CARGO_PKG_VERSION")`.
- `command`는 raw `std::env::args()`를 저장하지 않는다. parsed command
  context에서 만든 redacted metadata이며 `raw_args_stored:false`를 포함한다.
  snapshot archive URL, local path, checksum, acknowledgement, sensitive path
  값은 role별 placeholder로 저장한다.
- `status`: `success`(코드 0) | `failed`(코드 3) | `invalid`(코드 4).
- `stages`는 사양 0200의 9단계가 항상 전부, 고정 순서로 들어간다.
  status 값: `ok` | `failed` | `skipped`.

### source.json (0903) — 사양 0200의 3절 규칙으로 채운다

```json
{
  "schema_version": "1",
  "run_id": "…",
  "input": { "raw": "./repo", "kind": "local-path" },
  "resolved_path": "/abs/repo",
  "git": {
    "is_repo": true,
    "branch": "main",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "detached": false,
    "dirty": true,
    "remotes": [ { "name": "origin", "url": "https://…" } ]
  },
  "snapshot": null
}
```

깃 저장소가 아니면 `"git": null`. 로컬 `inspect` 실행의 `snapshot`은
null. `snapshot` 명령으로 준비한 원격 압축 검사 실행은 다음 객체를
기록한다.

```json
{
  "url": "https://example.com/project.zip",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "archive_format": "zip",
  "extracted_path": "/abs/snapshot/source"
}
```

`url`은 사용자 정보, query, fragment 원문을 저장하지 않는다.
`sha256`은 소문자 64자리 hex로 기록한다.

### inventory.json (0904) — 사양 0400 참조

```json
{
  "schema_version": "1",
  "run_id": "…",
  "root": "/abs/repo",
  "policy": {
    "hidden_entries": "included",
    "git_dir": "excluded-from-entries",
    "ignore_rules": "not-applied",
    "symlinks": "recorded-not-followed"
  },
  "limits": { "max_files": null, "max_read_bytes_per_file": null },
  "entries": [
    { "path": "src/main.rs", "kind": "file", "size": 1234, "ext": "rs",
      "symlink_target": null }
  ],
  "skipped": [ { "path": ".git", "reason": "excluded-git-dir" } ],
  "totals": { "discovered": 120, "listed": 118, "skipped": 2 }
}
```

`policy` 네 키와 값 문자열은 위 그대로 고정이다.

### coverage.json (0905)

```json
{
  "schema_version": "1",
  "run_id": "…",
  "files_discovered": 118,
  "files_read": 1,
  "files_skipped": 2,
  "bytes_read_total": 1820,
  "read_files": [ { "path": "package.json", "bytes": 1820 } ],
  "skip_reasons": { "symlink": 1, "binary": 0, "unreadable": 0 },
  "confidence_note": "이름 기반 감지가 주 수단이며 내용 열람은 감지 규칙이 지정한 파일로 한정되었다."
}
```

- `files_discovered` = inventory `totals.discovered`.
- `files_read` = `read_files` 길이. "읽음"은 내용을 연 파일만 뜻한다
  (인벤토리 등재는 읽음이 아니다).
- `files_skipped` = inventory `totals.skipped`.
- `skip_reasons`는 네 키 모두 항상 존재(0이어도 기록). 단 `binary`는
  내용 열람 단계의 바이너리 판정 수이고, `symlink`/`unreadable`/
  `excluded-git-dir`는 inventory의 skipped 사유 집계다.
  `excluded-git-dir`도 키로 포함한다 — 키는
  `symlink`, `binary`, `unreadable`, `excluded-git-dir` 네 개 고정.
- `confidence_note`는 위 고정 문장.

### evidence.json (0906), findings.json (0907)

사양 0500의 3절·4절 구조 그대로:

```json
{ "schema_version": "1", "run_id": "…", "evidence": [
  { "id": "E0001", "path": "package.json", "kind": "content-line",
    "json_pointer": "/scripts/postinstall",
    "lines": { "start": 12, "end": 12 },
    "summary": "package.json에 postinstall 스크립트가 정의됨",
    "value_stored": false,
    "redacted_excerpt": "postinstall: <redacted-command>",
    "signal_labels": ["execution-related-candidate", "lifecycle-script"],
    "raw_excerpt_stored": false,
    "redaction_applied": false,
    "redaction_labels": [] } ] }
```

- execution-related evidence는 raw command/script body를 저장하지 않는다.
- `redacted_excerpt`는 command placeholder와 signal만 제공한다.
- `raw_excerpt_stored`와 `value_stored`는 기본적으로 `false`다.
- URL query/fragment/userinfo, token-like 값, bearer-like 값 등이 감지되면
  `redaction_labels`에 남기고 원문은 저장하지 않는다.

```json
{ "schema_version": "1", "run_id": "…",
  "findings": [
    { "id": "F0001", "category": "auto-exec-hook", "priority": "중간",
      "summary": "…", "detail": "…", "limitation": "…",
      "evidence": ["E0001"] } ],
  "limitations": ["…"] }
```

### dependencies.json (0985–0986)

```json
{
  "schema_version": "1",
  "run_id": "…",
  "manifests": [
    {
      "path": "package.json",
      "ecosystem": "npm",
      "dependencies": [
        { "name": "left-pad", "source_kind": "registry" }
      ]
    }
  ],
  "limitations": [],
  "note": "직접 의존성 이름과 출처 종류만 기록한다. 버전·URL·로컬 경로 원문은 저장하지 않는다."
}
```

- 현재 1차 구현은 읽을 수 있는 `package.json`의 직접 의존성만 요약한다.
- `path`는 `inventory.json`의 파일 경로여야 한다. V12가 검증한다.
- 버전 범위, URL, git 주소, 로컬 경로 원문은 저장하지 않는다.

### sectors.json (0951–0955)

```json
{
  "schema_version": "1",
  "run_id": "…",
  "sectors": [
    { "name": "(root)", "files": 3, "bytes": 4200, "estimated_tokens": 1050,
      "extensions": { "md": 2, "toml": 1 }, "detections": 1 },
    { "name": "src", "files": 14, "bytes": 80000, "estimated_tokens": 20000,
      "extensions": { "rs": 14 }, "detections": 0 }
  ],
  "suggested_read_order": ["Cargo.toml", "README.md", "src/main.rs"],
  "note": "읽기 계획 보조 자료이며 판단 근거가 아니다."
}
```

계산 규칙(`src/sectors.rs`):

- 섹터 = inventory `entries` 중 `kind=file`을 경로의 첫 구성 요소로 묶은
  것. 루트 직속 파일은 `(root)` 섹터(0952). 섹터 정렬은 이름 사전순,
  단 `(root)`가 항상 첫 번째.
- `files`: 파일 수. `bytes`: size 합. `estimated_tokens`:
  `ceil(bytes / 4)`(0953).
- `extensions`: ext별 파일 수, ext가 null인 파일은 키 `"(none)"`.
  키 사전순.
- `detections`: 해당 섹터 경로에 속한 감지(D01–D13 매치) 수.
- `suggested_read_order`(0954): 아래 순서로 이어 붙이고 중복은 처음
  것만 남긴다. 최대 200개로 자르고, 잘렸으면 note 끝에
  ` 읽기 순서는 200개로 잘렸다.`를 덧붙인다.
  1. 매니페스트 감지 경로(D01, D03, D04) 사전순
  2. 자동 실행 지점 중 파일 경로(D02, D05, D10, D11, D12 중 파일인 항목)
     사전순
  3. 진입점 후보: `src/main.rs`, `src/lib.rs`, `src/index.js`,
     `src/index.ts`, `main.py`, `app.py`, `index.js`, `index.ts`,
     `main.go` 중 존재하는 것 (이 순서)
  4. 깊은 분석 후보: 경로와 확장자 기반 언어 힌트가 깊은 분석 대상이면
     대표 진입점 우선, 언어명, 크기, 경로 순으로 정렬
  5. 나머지 파일 크기 오름차순(같으면 경로 사전순)
- `note` 고정 문장: `읽기 계획 보조 자료이며 판단 근거가 아니다.`(0955)

### sensitive.json (0961)

- `mode`: `exclude`, `redacted-summary`, `approved-raw` 중 하나.
- `first_approval`, `second_approval`: 승인 플래그 입력 여부.
- `review_ack_confirmed`, `raw_ack_confirmed`: CLI가 요구하는 ack 문구가
  정확히 입력됐는지 여부. 기본 `exclude`에서는 둘 다 false다.
- `approved_paths`, `unapproved_paths`: 민감 후보 경로 중 승인·미승인 목록.
- `raw_content_stored`: 항상 false. 원문은 산출물에 저장하지 않는다.

### gates.json (0962–0965)

- `sensitive_raw_review`, `execution_review`: 승인 필요 여부, 사람에게 보여줄
  문구, 경로 목록, 구조화된 ack 문구 목록을 담는다.
- 민감 후보 원문 승인 게이트의 `acknowledgements`는
  `review-sensitive-candidates`와
  `include-approved-sensitive-raw-in-diagnostic-input` 순서다.
- 실행 게이트는 현재 별도 ack 문구가 없으므로 `acknowledgements`는 빈
  배열이다.

### review.json (0981–0984)

- `counts`는 발견사항 수, 승인 후보 수, 슬라이스 수, 한도 초과 슬라이스 수와
  `deep_analysis_candidates`를 기록한다.
- `required_actions`는 `sensitive-raw-review`,
  `execution-model-input-review`, `execution-command-review`,
  `oversized-slice-review` 등을 포함할 수 있다.
- 각 액션의 `acknowledgements`는 대응하는 `gates.json` 게이트의 배열과
  일치해야 한다. 후속 도구는 긴 승인 문구를 파싱하지 않고 이 배열을
  승인 입력 계약으로 사용한다.

### security.json (0987, 1406, 1429)

```json
{
  "schema_version": "1",
  "run_id": "…",
  "verdict": "approval-required",
  "action_required": true,
  "no_exec": "이 검사는 대상 저장소의 명령, 스크립트, 훅, 바이너리, 빌드, 테스트, 워크플로, 패키지 매니저, 컨테이너를 실행하지 않았다.",
  "counts": {
    "findings_total": 3,
    "high_priority_findings": 0,
    "medium_priority_findings": 2,
    "sensitive_candidates": 1,
    "automatic_execution_candidates": 1,
    "execution_related_candidates": 1,
    "deep_analysis_candidates": 1,
    "slices_total": 8,
    "slices_over_token_limit": 0
  },
  "required_actions": [],
  "default_model_excluded_paths": [".env", "setup.sh"],
  "limitations": ["…"],
  "references": [
    "review.json",
    "findings.json",
    "evidence.json",
    "gates.json",
    "slices.json",
    "sensitive.json"
  ],
  "note": "다른 도구가 먼저 읽기 쉬운 보안 요약이다. 새 파일을 읽거나 안전을 보증하지 않으며 원천 산출물을 함께 확인해야 한다."
}
```

- `verdict`, `counts`, `required_actions`, `default_model_excluded_paths`는
  `review.json`과 일치해야 한다.
- `action_required`는 `review.json.required_actions[].required` 중 하나라도
  참이면 참이다.
- `limitations`는 `findings.json.limitations`와 일치한다.
- `references`는 위 여섯 원천 산출물을 모두 포함한다.
- 이 파일은 다른 도구가 우선 읽기 쉬운 짧은 보안 요약이며, 새 대상 파일을
  읽거나 안전 여부를 보증하지 않는다.

### connection_graph.json / analysis_plan.json

- `connection_graph.json`은 파일, 매니페스트, lifecycle script, hook,
  workflow, dependency, sensitive candidate, prompt-injection surface, gate를
  노드와 엣지로 기록한다. 원문 command body는 저장하지 않는다.
- `scenarios[]`는 `npm install`, `docker build`, `make`, `git commit with
  hooks`, `open folder in VS Code` 같은 사용자 행동이 어떤 노드에 닿는지와
  어떤 gate에 막히는지를 기록한다.
- `analysis_plan.json`은 unit-analysis allowed/forbidden path, 질문, 의존
  unit, cross-unit task를 기록한다. 이는 agent 분석 계획이며 안전 보증이
  아니다.

### architecture_map.json / relation_map.json / source_landmarks.json / visualization_index.json / architecture.html

- `architecture_map.json`은 repo shape, sector, entrypoint, architecture
  summary를 기록한다. `architecture_summary.safe_claim_made`는 항상 false다.
- `relation_map.json`은 scenario, script, manifest, config, dependency, gate
  관계를 기록한다. 원문 command body는 저장하지 않는다.
- `source_landmarks.json`은 권장 읽기 순서, 기본 미열람 경로, gate-before-reading
  경로를 기록한다.
- `visualization_index.json`은 `architecture.html`의 view와 privacy 계약을
  기록한다. `raw_sensitive_content_included:false`,
  `target_repo_js_executed:false`, `external_network_required:false`를 유지한다.
- `architecture.html`은 Git-SCV가 생성한 정적 viewer다. target repository
  HTML/JS를 실행하지 않고, 외부 network fetch 없이 redacted/sanitized data만
  렌더링한다.

### cross_unit_analysis.json / synthesis.json / followup_plan.json

- `cross_unit_analysis.json`은 scenario별 reachable node, blocked gate,
  sensitive-plus-execution 같은 조합 위험, unresolved/followup 상태를
  집계한다.
- `synthesis.json`은 전체 진단 artifact다. `safe_claim_made:false`를
  유지하고, 악성 부재·설치 안전성·실행 안전성 등 결론낼 수 없는 범위를
  명시한다.
- `followup_plan.json`은 미해결 gate, unresolved edge, conflict, coverage
  gap에 대한 다음 라운드 질문과 필요한 사용자 승인을 기록한다.
- `git-scv validate-unit`, `validate-units`, `synthesize`,
  `followup-plan`, `validate-followup`은 이 artifact set과 agent-provided
  unit-analysis JSON의 형식, evidence link, path boundary를 검증하거나
  요약한다. semantic truth나 malware absence는 검증하지 않는다.

### report.html (0991–0993)

- `report.html`은 실행별 브라우저용 사람 읽기 리포트다. 기존 `RunData`만
  렌더링하며 대상 저장소 파일을 새로 읽지 않는다.
- `report.md`와 같이 민감 후보 처리 절을 포함하고, 1차·2차 승인 ack 확인
  상태를 표시한다.
- `report.md`와 `report.html`은 깊은 분석 후보 수를 표시한다.
- 승인 게이트 절은 필요한 ack 문구를 `review.json.required_actions[].acknowledgements`
  값에서 표시한다.

### slices.json (0971–0972)

- `slices.json`은 `sectors.json`의 `suggested_read_order`와 `gates.json`의
  승인 후보 목록을 조합한 경로 기반 모델 입력 계획이다. 파일 본문은
  포함하지 않는다.
- 각 파일 항목은 경로와 확장자 기반의 `language_hint`를 기록할 수 있다.
  깊은 분석 대상 언어이면 `deep_analysis_candidate=true`로 표시한다.
  이 힌트는 본문 판독 결과가 아니며, 안전 보증이나 악성 여부 판단이 아니다.
- 민감 후보, 자동 실행 후보, 실행 관련 후보는 별도 승인 전
  `default_model_input=false`로 기록한다.

### report.md (0908) — 아래 템플릿 그대로, 섹션 순서 변경 금지

```markdown
# git-scv 검사 리포트

- 실행 번호: {run_id}
- 도구: git-scv {버전}
- 시작: {started_at} / 종료: {finished_at}

## 원본

- 입력 경로: {input.raw}
- 해석된 경로: {resolved_path}
- 깃 정보: {요약 또는 "깃 정보 없음"}
- 스냅샷: 없음

## 범위

- 발견 항목: {discovered} / 나열: {listed} / 건너뜀: {skipped}
- 내용을 읽은 파일: {files_read}개, {bytes_read_total}바이트
- 정책: 무시 규칙 미적용, 심볼릭 링크 미추적, 탐색 한도 없음

## 민감 후보 처리

- 모드: {sensitive_mode}
- 후보: {sensitive_candidates}개 / 원문 승인 경로: {approved_paths}개
- 승인 ack 확인: 1차 {review_ack} / 2차 {raw_ack}
- 원문 저장: 없음
- 메모: {sensitive_note}

## 승인 게이트

- 민감 후보 원문 승인 필요: {sensitive_gate}
- 실행 승인 필요: {execution_gate}
- 자동 실행 후보: {auto_exec_count}개 / 실행 관련 후보: {execution_related_count}개

## 읽기 슬라이스

- 슬라이스: {slice_count}개
- 깊은 분석 후보: {deep_analysis_candidates}개
- 슬라이스당 최대 추정 토큰: {slice_limit}
- 한도 초과 단일 파일 슬라이스: {over_limit_slices}개
- 기본 모델 입력 정책: 민감 후보와 실행 후보 제외

## 기계 요약

- 검토 판정: {review_verdict}
- 필요한 후속 액션: {required_actions}개
- 필요한 후속 액션 목록: {required_action_list}

## 의존성 요약

- 매니페스트: {dependency_manifest_count}개
- 직접 의존성 이름: {dependency_count}개
- 메모: 버전·URL 원문 미저장

## 발견사항

| 번호 | 우선순위 | 요약 | 증거 |
| --- | --- | --- | --- |
| F0001 | 중간 | … | E0001 |

## 한계

- {limitations 항목들}

## 무실행 확인

이 검사는 대상 저장소의 명령, 스크립트, 훅, 바이너리, 빌드, 테스트, 워크플로, 패키지 매니저, 컨테이너를 실행하지 않았다.
```

- 깃 정보 요약 형식: `가지 {branch}, 커밋 {commit 앞 12자}, 미커밋 변경 {있음|없음|확인 안 됨}`.
  분리 HEAD면 `가지 (분리 HEAD), …`.
- 발견사항이 0건이면 표 대신 `발견사항 없음` 한 줄(0908).
- 마지막 문장은 한 글자도 바꾸지 않는다 — V05가 이 문자열을 그대로
  찾는다(0804).

## 3. 검증 관문 — validate.rs (0800)

두 함수로 나뉜다:

- `validate(&RunData)` — artifacts 쓰기 **전** 메모리 검증: V02–V04, V06–V24
- `verify_outputs(out_dir)` — 쓰기 **후** 디스크 검증: V01, V05, V25

| 번호 | 검사 | 실패 문자열(그대로) |
| --- | --- | --- |
| V01 | 45개 inspect/analysis 산출물 파일이 모두 존재 (0801, 0901) | `V01: 산출물 파일 누락: {이름들}` |
| V02 | 모든 finding의 evidence id가 evidence 목록에 실재 (0802) | `V02: 증거 없는 발견사항: {finding id들}` |
| V03 | inventory 불변식 `discovered == listed + skipped` | `V03: 인벤토리 집계 불일치` |
| V04 | `read_files`의 bytes 합 == `bytes_read_total` | `V04: 커버리지 바이트 불일치` |
| V05 | report.md에 무실행 고정 문장 포함 (0804) | `V05: 무실행 문장 누락` |
| V06 | 낮은 확신 조건이면 한계에 낮은 확신 문장 존재 (0805) | `V06: 낮은 확신 표시 누락` |
| V07 | `sensitive.json` 후보와 `gates.json` 민감 후보가 일치 | `V07: 민감 후보 게이트 불일치` |
| V08 | 승인 프롬프트 경로가 민감 후보와 실행 후보 경로 집합과 일치 | `V08: 승인 프롬프트 경로 불일치` |
| V09 | `slices.json` 파일 경로가 `inventory.json` 파일 경로에 존재 | `V09: 인벤토리에 없는 슬라이스 경로: {경로들}` |
| V10 | 민감 후보가 기본 모델 입력으로 표시되지 않음 (0972) | `V10: 민감 후보 기본 모델 입력 허용: {경로들}` |
| V11 | 슬라이스 승인 필요 플래그가 파일별 민감·실행 후보 여부와 일치 | `V11: 슬라이스 승인 플래그 불일치: {slice id들}` |
| V12 | 의존성 매니페스트 경로가 `inventory.json` 파일 경로에 존재 (0986) | `V12: 인벤토리에 없는 의존성 매니페스트 경로: {경로들}` |
| V13 | 주요 JSON 산출물의 `schema_version`과 `run_id`가 실행 계약과 일치 (0806) | `V13: 산출물 공통 메타데이터 불일치: {이름들}` |
| V14 | `review.json` 판정, 집계, 기본 제외 경로가 원천 산출물과 일치 (0982) | `V14: review.json 요약 불일치: {필드들}` |
| V15 | `review.json.required_actions`가 게이트와 한도 초과 슬라이스 여부와 일치 (0983, 0984) | `V15: review.json 필수 액션 불일치: {항목들}` |
| V16 | 게이트 후보 경로가 `inventory.json` 항목 경로에 존재 (0963) | `V16: 인벤토리에 없는 게이트 후보 경로: {경로들}` |
| V17 | 증거 경로가 `inventory.json` 항목 경로에 존재 | `V17: 인벤토리에 없는 증거 경로: {경로들}` |
| V18 | 증거 형태별 줄 범위와 excerpt 저장 규칙을 지킴 | `V18: 증거 형태 불일치: {증거 id들}` |
| V19 | 실행 후보가 기본 모델 입력으로 표시됨 (0972) | `V19: 실행 후보 기본 모델 입력 허용: {경로들}` |
| V20 | 슬라이스 파일의 언어 힌트와 깊은 분석 후보 플래그가 인벤토리 경로·확장자와 일치 (1403A) | `V20: 슬라이스 언어 힌트 불일치: {경로들}` |
| V21 | `sectors.suggested_read_order`가 인벤토리 파일 경로만 중복 없이 참조 (0954) | `V21: 읽기 순서 경로 불일치: {세부}` |
| V22 | `slices.json` 파일 순서가 `sectors.suggested_read_order`를 보존 (0971) | `V22: 슬라이스 읽기 순서 불일치: {세부}` |
| V23 | `slices.json` 파일 경로가 중복 없이 한 번만 등장 (0971B) | `V23: 중복 슬라이스 파일 경로: {경로들}` |
| V24 | `security.json` 요약이 `review.json`, `findings.json`과 일치하고 원천 참조를 포함 (0987, 1429) | `V24: security.json 요약 불일치: {필드들}` |
| V25 | JSON/Markdown/HTML 산출물에 URL query/fragment, fake token marker, bearer/key-like marker, raw Authorization-like value, HTML injection payload가 남지 않음 | `V25: 산출물 누출 의심: {항목들}` |

- V06의 낮은 확신 조건: `findings`가 0건이거나 `files_read`가 0이면,
  findings.json `limitations`와 report.md 한계 절에 고정 문장
  `이 검사는 증거가 충분하지 않아 낮은 확신의 결과다.`가 있어야 한다.
  (findings 생성 단계가 이 문장을 넣고, V06은 그것을 확인한다.)
- 하나라도 실패하면 `ScvError::Validation(실패 문자열 목록)` → 종료 코드 4.
  실패 목록은 stderr와 run.json(`status:"invalid"`)에 남는다(0801–0805).
