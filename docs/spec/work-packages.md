# 작업 패키지와 시험 매트릭스 — 코더 실행 지침

작업 방식은 시험 주도다. **시험은 이미 작성되어 저장소에 들어 있다.**
코더의 일은 `src/` 스텁의 `todo!()`를 채워 시험을 빨강에서 초록으로
만드는 것이다. 시험을 고치거나 지우는 것은 사양 변경이며, 사양 문서
(docs/spec/)를 먼저 고치지 않는 한 금지다.

## 0. 작업 규칙 (전 작업 공통)

1. 작업 시작 전 해당 WP의 시험을 실행해 **빨강을 확인**한다.
2. 시험이 초록이 될 때까지만 구현한다. 시험에 없는 동작을 추가하지
   않는다.
3. 끝나면 `cargo fmt`, `cargo clippy --all-targets`, `cargo test`
   전부 통과 상태로 닫는다. 공개 커밋은 버전 접두어
   `v{버전}: {요약}`을 포함하고, 로컬 작업 패키지 기록에는 닫은
   요구사항 번호를 남긴다.
4. 의존성 추가 금지, 모듈 추가·이동 금지(architecture.md가 헌법),
   프로세스 생성 API 금지(T09가 기계적으로 잡는다).
5. 막히면 코드를 우회하지 말고 사양 문서의 빈틈을 보고한다. 사양에
   없는 결정을 코드에 넣지 않는다.

## 1. 작업 패키지 (의존 순서)

| WP | 범위 | 사양 | 초록으로 만들 시험 | 완료 조건 |
| --- | --- | --- | --- | --- |
| WP0 | rustup 설치, `cargo build` 통과 | — | (빌드 자체) | 스텁 상태로 `cargo build`와 `cargo test` 실행 가능(시험은 빨강) |
| WP1 | cli.rs, errors.rs, main.rs | 0100-cli.md | T01, T02 | `--help`에 무실행 문구, 종료 코드 4종 |
| WP2 | source.rs | 0200-flow.md 3절 | T07 (+T06 일부) | 자기 저장소 self-inspect에서 가지·커밋·변경 정확 |
| WP3 | walk.rs, safety.rs | 0400-walk.md | T08 | 심볼릭 링크 미추적, .git 제외, 집계 불변식 |
| WP4 | detect.rs | 0500-detect.md 1–2절 | T03 | 규칙 D01–D13 전부, D13의 내용 미열람 |
| WP5 | evidence.rs, findings.rs | 0500-detect.md 3–4절 | T04, T05 | 증거 없는 발견사항이 타입에서 거부됨 |
| WP6 | validate.rs | 0900-artifacts.md 3절 | T11 | V01–V25 각각 개별 결함 주입 시 개별 실패 |
| WP7 | artifacts.rs, report.rs, dependencies.rs, sectors.rs, sensitive.rs, gates.rs, slices.rs, review.rs, web_report.rs, graph.rs, visualization.rs, synthesis.rs | 0900-artifacts.md 1–2절 | T06, T10 | 31개 inspect 산출물, 결정적 바이트, 리포트/시각화 템플릿 일치 |
| WP8 | inspect.rs 조립 | 0200-flow.md 1–2절 | T06, T07 전부 | 중간 단계 강제 실패 시에도 run.json 생성 |
| WP9 | 마무리 | 전체 | T01–T12 전부 | fmt·clippy 무경고, CI 초록 |

병렬: WP2·WP3·WP4는 WP1 뒤 동시 진행 가능. WP5는 WP4 뒤,
WP6·WP7은 WP5 뒤, WP8은 WP2+WP3+WP7 뒤.

## 2. 시험 매트릭스 (시험 파일은 `tests/`에 이미 있음)

| 시험 | 파일 | 단언 | 요구사항 |
| --- | --- | --- | --- |
| T01 | tests/cli.rs | 부재 경로·파일 경로 입력 → 코드 2, 고정 오류 문구 | 0024, 1301 |
| T02 | tests/cli.rs | 비어 있지 않은 --out → 코드 2, 아무 파일도 안 씀 | 9006 |
| T03 | tests/detect.rs | D01–D13 각각 고정 입력으로 매치·문구 검증 | 0501–0507 |
| T04 | tests/findings.rs | `Finding::new(.., 빈 증거)` 가 Err | 0605, 1304 |
| T05 | tests/findings.rs | D13 파일 내용 문자열이 어떤 산출물에도 없음 | 1103, 1104 |
| T06 | tests/integration.rs | 고정 저장소 → 31개 inspect 산출물, 스키마 필수 필드, 승인 게이트·읽기 슬라이스·보안 요약·그래프·시각화·합성·웹 리포트 확인 | 1302, 1303, 8002–8005 |
| T07 | tests/integration.rs | 깃 아닌 디렉터리 → 성공, `"git": null` | 0303 |
| T08 | tests/integration.rs | `discovered == listed + skipped`, 심링크는 skipped로만 집계 | 0406 |
| T09 | tests/no_exec.rs | src/ 전체에 `Command::`, `.spawn(`, `.output(`, `.status(` 부재 | 1305, 1307 |
| T10 | tests/integration.rs | 같은 입력 2회 → run.json 제외 산출물 바이트 동일 | (결정성) |
| T11 | tests/validate.rs | V01–V25 각 결함 주입 → 해당 V번호로만 실패 | 0801–0806, 0901, 0954A, 0963, 0971A, 0971B, 0972, 0973, 0982–0987 |
| T12 | tests/integration.rs | 승인 원문 민감 후보 진단은 승인 경로만 읽고 원문을 산출물에 저장하지 않음 | 1120–1122, 1211–1213 |

## 3. 고정 저장소 (tests/fixtures/sample-repo/)

정적 파일은 저장소에 들어 있다. 깃에 담기 어려운 항목(심볼릭 링크,
NUL 바이너리)은 시험 헬퍼 `tests/common/mod.rs`의 `materialize()`가
임시 디렉터리에 픽스처를 복사한 뒤 생성한다. 시험은 항상 임시 복사본을
검사하고 원본 픽스처는 수정하지 않는다.

| 항목 | 역할 |
| --- | --- |
| `package.json` (postinstall 포함) | D01, D02 |
| `setup.sh` | D09 |
| `.github/workflows/ci.yml` | D08 |
| `.env` (가짜 토큰 `FAKE_TOKEN_DO_NOT_READ=abc123secretvalue`) | D13, T05 |
| `build.rs` | D05 |
| `.envrc` | D10 |
| `.vscode/tasks.json` | D11 |
| `Makefile` | D06 |
| `src/index.js`, `lib/util.js` | 일반 파일, 섹터 검증 |
| (시험 시 생성) `link-out` → `/tmp` 심볼릭 링크 | 9007 |
| (시험 시 생성) `blob.bin` (NUL 포함) | 바이너리 판정 |

## 4. 완료 기준 대조표 (8000대)

| 완료 기준 | 확인 방법 |
| --- | --- |
| 8001 로컬 깃 저장소 성공 | git-scv 저장소 자신 self-inspect (WP9에서 수동 1회 + T06) |
| 8002 inspect 산출물 31개 생성 | T06 |
| 8003 리포트 핵심 절 포함 | T06 (report.md 절 제목 검사) |
| 8004 발견사항이 증거 참조 | T04, T11(V02) |
| 8005 건너뜀·한도 기록 | T06, T08 |
| 8006 대상 명령 무실행 | T09 |
| 8007 핵심 시험 통과 | CI (`cargo test`) |
