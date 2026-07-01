# 에이전트 안내 — git-scv 호출 계약

이 문서는 코딩 에이전트(Claude Code, Codex 등)가 git-scv를 쓰는
방법이다. 사람도 같은 절차를 따를 수 있다.

## 1. 언제 쓰는가

사용자가 낯선 저장소에 대해 "설치/빌드/실행해도 되나", "이 레포 뭐 하는
레포냐"를 물을 때, **설치·빌드·테스트·실행을 하기 전에** 먼저 호출한다.

## 2. 호출 (1201, 1202)

사용자가 원터치 분석을 원하면:

```sh
git-scv scan <repo-path> --goal install --worker codex
```

Codex/Claude CLI가 없거나 에이전트가 직접 각 slice를 처리할 때는:

```sh
git-scv scan <repo-path> --goal install --worker manual
git-scv review <repo-path> --goal install
```

정적 preflight만 필요하면:

```sh
git-scv inspect <repo-path> --out <run-dir>
```

- 컴파일된 실행 파일을 호출한다. `cargo run`은 개발 경로다(1201).
- `<run-dir>`은 새 경로 또는 빈 디렉터리여야 한다. 비어 있지 않으면
  종료 코드 2로 거부된다.
- 종료 코드: 0 성공 / 2 입력 오류 / 3 검사 실패 / 4 산출물 검증 실패.
- stdout은 파싱하지 않는다. 판단은 산출물 파일로만 한다(1203).
- `scan --worker codex|claude`가 허용하는 프로세스 실행은 target repo가
  아니라 사용자의 터미널에 이미 준비된 worker CLI뿐이다. git-scv는
  OAuth/token 파일을 읽거나 저장하지 않는다.

## 3. 산출물 읽기 순서 (1203, 1206)

`<run-dir>`에서 이 순서로 읽는다:

1. `brief.json` / `brief.md` — verdict, action_required, required_actions,
   `artifact_manifest_sha256`, `source_fingerprint_hash`를 먼저 확인한다.
2. `artifact_manifest.json` — artifact-contract-v2, hash chain, post-write
   validation, leak scan 상태를 확인한다.
3. `run.json` — status가 `success`인지, 어느 단계가 실패했는지.
4. `source.json` — 무엇을 검사했는지(경로, 깃 가지·커밋·미커밋 변경)와
   source fingerprint를 확인한다.
5. `inventory.json` — 어떤 경로가 파일·디렉터리·심볼릭 링크로 등재되거나
   건너뛰어졌는지 확인한다.
6. `coverage.json` — 무엇을 보았고 무엇을 보지 못했는지. 이 범위 밖의
   주장을 하지 않는다.
7. `findings.json` — 발견사항과 한계를 확인한다.
8. `evidence.json` — 발견사항마다 `evidence` 배열의 증거 번호를 따라가
   근거를 확인한다. 증거 없는 주장은 산출물에 존재하지 않는다.
9. `dependencies.json` — 직접 의존성 이름과 출처 종류만 확인한다. 버전
   범위, URL, 깃 주소, 로컬 경로 원문은 저장되지 않는다.
10. `sectors.json` — 저장소를 깊이 읽어야 할 때의 읽기 계획. 섹터별
   추정 토큰으로 컨텍스트 예산을 배분하고, `suggested_read_order`
   순서로 연다. 판단 근거가 아니라 계획 보조 자료다(0955).
11. `sensitive.json` — 민감 후보 진단 모드, 승인 경로, 후보별 원문
   열람 여부를 확인한다. 원문은 산출물에 저장되지 않는다.
12. `gates.json` — 모델 입력 전 민감 후보 원문 승인 게이트와
   설치·빌드·테스트·실행 전 자동 실행 후보 승인 게이트를 확인한다.
13. `gate_decisions.json` — source/artifact/action-bound 승인 결정 envelope.
    자동 승인은 생성되지 않는다.
14. `slices.json` — 본문을 열기 전, 어떤 경로 묶음을 어떤 순서로 읽을지
    확인한다. 이 파일은 경로·크기·추정 토큰·언어 힌트·승인 플래그만
    담고 본문은 담지 않는다.
15. `review.json` — 판정, 집계, 기본 모델 입력 제외 경로, 필요한 후속
    액션을 확인한다.
16. `security.json` — 다른 도구가 먼저 읽기 쉬운 보안 요약. 판정, 필수
    액션, 제외 경로, 한계, 원천 산출물 참조를 확인하되 안전 보증으로
    취급하지 않는다.
17. `supported_surfaces.json` — parsed/name-detected/unsupported/parse-failed
    surface matrix를 확인한다.
18. `connection_graph.json` — 사용자 행동이 어떤 실행/민감/모델입력 표면과
    gate에 닿는지 확인한다.
19. `reachability_scenarios.json` — install/build/test/run/open-editor/hook
    행동별 reachable node와 blocked_by gate를 확인한다.
20. `architecture_map.json` — repo shape, sector, entrypoint, architecture
    summary를 확인한다.
21. `relation_map.json` — scenario, script, manifest, config, gate 사이 관계를
    확인한다.
22. `source_landmarks.json` — 권장 읽기 순서, 기본 미열람 경로, gate-before-reading
    경로를 확인한다.
23. `visualization_index.json` — `architecture.html` view와 privacy 계약을
    확인한다.
24. `analysis_plan.json` — unit별 allowed/forbidden path와 cross-unit task를
    확인한다.
25. `cross_unit_analysis.json` — 조합 위험, unresolved edge, follow-up 필요
    여부를 확인한다.
26. `synthesis.json` — 전체 진단과 결론 불가능 범위를 확인한다.
27. `followup_plan.json` — 다음 라운드 질문과 필요한 사용자 승인을 확인한다.
28. `agent_receipt.json` — receipt가 생성된 경우, agent가 어떤 manifest와
    source fingerprint에 묶인 artifact set을 읽었다고 기록했는지 확인한다.
29. `report.md` — 사용자에게 보여줄 요약. 필수 액션 목록을 먼저 확인한 뒤
    그대로 인용해도 된다.
30. `report.html` — 브라우저에서 확인할 때 쓰는 사람용 요약. 필요한 ack
    문구가 있는 필수 액션은 승인 게이트 절에 표시된다.
31. `architecture.html` — repo 구조, 실행 시나리오, script 관계, gate,
    coverage, source landmark, synthesis를 보는 기본 동적 HTML. target repo
    HTML/JS는 실행하지 않는다.

에이전트가 사람에게 먼저 보여줄 수 있는 요약은 `brief.md`,
`architecture.html`, `report.md`, `report.html`이다. 단, 후속 자동 판단은
반드시 `review.json.required_actions`, `security.json.references`,
`gates.json`, `slices.json`, `source_landmarks.json`, `visualization_index.json`의
구조화된 JSON 값을 기준으로 한다.

`review.json.required_actions`의 id는 아래 값들을 포함할 수 있다.

- `sensitive-raw-review`: 민감 후보 원문을 진단 입력이나 모델 입력에
  포함하려면 2중 승인과 경로별 승인이 필요하다. 필요한 ack 문구는
  `acknowledgements` 배열에서 읽는다.
- `execution-model-input-review`: 자동 실행 후보와 실행 관련 후보는 모델
  입력 전에 사용자에게 경로 목록을 보여준다.
- `execution-command-review`: 설치·빌드·테스트·실행 승인 전에는 exact command
  envelope와 source/artifact binding이 필요하다.
- `oversized-slice-review`: 단일 파일 슬라이스가 토큰 계획 한도를 넘었다는
  경고다. 안전 판정이 아니며, 분할·요약·부분 열람 전략을 따로 세운다.

## 4. 민감 후보 게이트 (1107–1109, 1113–1115, 1120–1122, 1210–1213)

`gates.json.sensitive_raw_review.approval_required`가 참이면, 그 파일은
무시하거나 안전하다고 간주하지 않는다. 기본 검사는 원문을 열지 않았으므로,
에이전트는 설치·빌드·테스트·실행·모델 입력 전에
`gates.json.sensitive_raw_review.paths`를 사용자에게 보여주고 별도 결정을
받아야 한다.

사용자에게 제시할 1차 선택지는 아래 셋이다.

1. 제외: 후보 파일은 깊은 분석과 모델 입력에서 제외한다. 기본값이다.
2. 가린 로컬 요약: 로컬에서 값 원문을 저장하지 않는 요약만 만든다.
3. 승인 경로 원문 분석: 사용자가 지정한 경로만 별도 진단 입력에 포함한다.

3번을 고른 경우에도 바로 원문을 모델 입력에 넣지 않는다. 에이전트는
2차 승인 질문으로 원문 분석 대상 경로 목록을 다시 보여주고, 사용자가
그 경로 목록을 명시적으로 승인한 뒤에만 해당 경로를 별도 진단 입력에
포함한다. 1차 승인만 있고 2차 승인이 없으면 원문 분석은 수행하지 않는다.

승인 없이 비밀값 후보 파일의 원문을 모델 입력에 넣지 않는다. 승인된
경로를 분석하더라도 산출물에는 원문을 저장하지 않는다.

## 5. 슬라이스와 모델 입력 (0971, 1211, 1410)

깊은 분석이나 모델 호출이 필요하면 `slices.json`을 읽는다.

- `slices[].files[].default_model_input`이 `false`인 파일은 기본 모델 입력에
  넣지 않는다.
- `slices[].files[].language_hint`와
  `slices[].files[].deep_analysis_candidate`는 경로와 확장자 기반 라우팅
  힌트일 뿐이다. 안전 여부나 악성 여부 판단이 아니다.
- `slices[].requires_sensitive_raw_approval`이 참이면, 해당 슬라이스는
  민감 후보 원문 2중 승인 전에는 원문 입력으로 쓰지 않는다.
- `slices[].requires_execution_approval`이 참이면, 설치·빌드·테스트·실행
  승인 질문 전에 관련 경로를 사용자에게 보여준다. 실행 관련 파일이
  깊은 분석 후보여도 승인 전 기본 모델 입력에 넣지 않는다.
- `over_token_limit`이 참인 슬라이스는 단일 파일이 한도를 넘은 경우다.
  에이전트는 파일 일부만 읽거나 별도 요약 전략을 세워야 하며, 도구가
  그 파일 본문을 자동으로 나눠 읽었다고 말하면 안 된다.

슬라이스는 경로 계획일 뿐이다. 파일 본문을 실제로 열기 전에 항상
`gates.json`의 승인 경계와 `review.json.required_actions`를 먼저 확인한다.

## 6. 해석 규칙 (1204)

- 발견사항은 **보증이 아니라 범위가 제한된 검토 출력**이다.
  "발견사항 없음"은 허가 신호가 아니다 — coverage와 한계 안에서만 말한다.
- 우선순위 의미: `높음`(진입·설치만으로 실행될 수 있는 지점) >
  `중간`(설치·빌드 과정에서 자동 실행될 수 있는 지점) >
  `낮음`(검토할 가치가 있는 존재) > `정보`(맥락).
- 사용자에게 전달할 때는 발견사항 요약과 함께 반드시 한계
  (`findings.json`의 `limitations`)를 같이 전달한다.
- `schema_version`/`contract_version`이 모르는 값이면 자동 판단하지 말고
  report.md와 artifact manifest를 사람에게 보여준다. v0.2 artifact는
  v0.3 artifact-contract-v2와 호환되지 않으므로 재검사가 필요하다.

## 7. 다음 단계 경계 (1205)

산출물을 읽은 뒤에도, 대상 저장소의 설치·빌드·테스트·실행·스크립트는
**사용자의 명시적 승인 전에는 진행하지 않는다**. 발견사항 중
`auto-exec-hook` 분류(우선순위 중간 이상)는 승인 요청 시 사용자에게
구체적으로 보여준다. 예:

> 이 저장소는 `npm install`만으로 postinstall 스크립트(package.json
> 12행)가 실행됩니다. 설치를 진행할까요?

`secret-candidate`가 남아 있으면 설치 승인 질문과 별도로 민감 후보
결정을 먼저 받는다. 비밀값 후보 파일명이 실행 후보처럼 쓰였거나 미상의
출처에서 받은 스크립트로 의심되는 경우, 일반 설치 승인으로 퉁치지 말고
별도 민감 후보 진단을 제안한다.
