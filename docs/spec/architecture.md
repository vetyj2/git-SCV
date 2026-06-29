# 아키텍처 — 기능 핵심, 명령 껍질 (functional core, imperative shell)

이 문서는 코드 구조의 헌법이다. 모듈을 어디에 두고, 누가 누구를
의존할 수 있는지는 여기서 정한 대로만 한다. 구조 변경은 이 문서를
먼저 고친 뒤에만 가능하다.

## 1. 계층

```text
            ┌─────────────────────────────────────────┐
  껍질(IO)  │ main.rs · cli.rs                         │  진입, 인자, 종료 코드
            │ source.rs · walk.rs · detect.rs(읽기)    │  대상 저장소 "읽기"만
            │ snapshot.rs                              │  원격 압축 스냅샷 준비
            │ artifacts.rs(쓰기) · safety.rs           │  출력 디렉터리 "쓰기"만
            ├─────────────────────────────────────────┤
  조립      │ inspect.rs                               │  단계 순서 조립(0201)
            ├─────────────────────────────────────────┤
  핵심(순수)│ model.rs · evidence.rs · findings.rs     │  파일시스템·시계 접근 금지
            │ validate.rs(메모리 검증) · report.rs     │  입력 → 출력 순수 함수
            │ sectors.rs                               │
            ├─────────────────────────────────────────┤
  기반      │ errors.rs                                │  모두가 의존 가능
            └─────────────────────────────────────────┘
```

의존 방향 규칙:

- 핵심(순수) 모듈은 껍질 모듈을 **절대** 의존하지 않는다. `std::fs`,
  `std::env`, 시계, `gix`, `walkdir`를 import하지 않는다.
- 껍질 모듈끼리는 서로 의존하지 않는다. 연결은 `inspect.rs`만 한다.
- 모든 데이터 타입은 `model.rs` 한 곳에 둔다. 단계 함수는
  `model` 타입을 받고 `model` 타입을 돌려준다.
- 예외: `validate::verify_outputs`(디스크 확인, V01·V05)는 IO지만
  validate.rs에 둔다 — 검증 규칙을 한 파일에서 읽을 수 있는 가치가
  더 크다. 이 함수 하나만 예외다.

이 구조의 이유: 핵심이 순수 함수면 시험이 픽스처 없이 값만으로 돌고,
탐지 규칙 추가 같은 미래 변경이 껍질을 건드리지 않는다. 무실행 원칙도
지키기 쉬워진다 — 프로세스·네트워크 API가 들어올 자리가 껍질뿐이고,
껍질은 작다.

## 2. 데이터 흐름 (단방향, 0201)

```text
InspectArgs
  → source::identify   → SourceInfo      (껍질: 저장소 읽기)
  → walk::walk         → Inventory       (껍질: 저장소 읽기)
  → detect::detect     → Vec<Detection>  (껍질: package.json만 읽기)
  → evidence/findings  → EvidenceSet, FindingSet   (핵심: 순수)
  → sectors::build     → Sectors         (핵심: 순수)
  → validate::validate → Result          (핵심: 순수)
  → report::render     → String          (핵심: 순수)
  → artifacts::write_all                (껍질: 출력 쓰기)
  → validate::verify_outputs            (예외 IO)
  → run.json 기록                        (껍질, 항상 마지막)
```

데이터는 앞으로만 흐른다. 뒤 단계가 앞 단계를 다시 호출하거나, 단계가
전역 상태를 공유하는 구조는 금지한다.

`snapshot` 명령은 `snapshot.rs`에서 HTTPS 압축 바이트를 받고 체크섬을
검증한 뒤 안전한 항목만 `<snapshot-dir>/source`로 풀어 기존 `inspect`
흐름에 넘긴다. 이 입력 준비 단계도 대상 저장소의 명령, 스크립트, 훅을
실행하지 않는다.

## 3. 확장 규칙 (지속 가능성의 핵심)

- **탐지 규칙 추가** = ① 사양 0500 표에 행 추가 ② `detect.rs`의 규칙
  테이블 상수에 한 줄 추가 ③ 고정 문구 템플릿 추가 ④ 시험 한 개 추가.
  다른 파일은 건드리지 않는다. 이 4단계로 안 되는 규칙이면 사양을 먼저
  바꾼다.
- **산출물 필드 추가** = `schema_version`을 올리고(아래 4절), model.rs와
  사양 0900을 같이 바꾼다. 필드 제거·이름 변경은 메이저 변경이다.
- **새 입력 방식**(원격 스냅샷, 1401) = 기본 `inspect`에 섞지 않고 별도
  명령으로 추가한다. source.rs 옆에 새 껍질 모듈을 두고, 압축 내려받기와
  사용자 제공 체크섬 검증을 통과한 로컬 스냅샷만 기존 핵심 흐름에 넘긴다
  (9005). 핵심은 변하지 않는다.
- 의존성 추가 금지. 현재 런타임 의존성은
  `clap`, `serde`, `serde_json`, `walkdir`, `gix`, `time`, `sha2`, `ureq`,
  `zip`, `tar`, `flate2`다. `sha2`, `ureq`, `zip`, `tar`, `flate2`는
  snapshot 명령의 체크섬·HTTPS 다운로드·압축 해제 경계에 한정한다.
  여기서 늘리려면 이 문서를 먼저 고치고 사유를 남긴 뒤에만 한다.
  프로세스 생성 의존성은 추가하지 않는다.

## 4. 스키마 버전 정책

- `schema_version`은 문자열 숫자("1", "2", …).
- 필드 추가(하위 호환): 버전 유지 가능. 의미 변경·제거·이름 변경:
  버전 올림 + agent-guide.md 갱신.
- 에이전트는 모르는 버전을 만나면 report.md만 신뢰하도록 안내되어 있다.

## 5. 오류 규약

- 단계 함수는 `Result<T, ScvError>`만 돌려준다. 패닉으로 흐름을 제어하지
  않는다. `unwrap`/`expect`는 src/에서 금지하고(시험·고정 상수 제외),
  clippy 설정으로 막는다.
- 부분 실패(파일 하나 못 읽음 등)는 오류가 아니라 **기록**이다 —
  skipped, limitations로 남기고 계속 간다(0403). 오류는 단계 전체를
  진행할 수 없을 때만 낸다.
