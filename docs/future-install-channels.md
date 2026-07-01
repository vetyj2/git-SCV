# 추후 확장 메모 — 설치 채널 사전진단

이 문서는 현재 완료된 빌딩플랜을 변경하지 않는다. v0.3.3 이후 별도
검토할 수 있는 확장 아이디어만 기록한다.

## 목적

`git-scv`의 현재 핵심 가치는 낯선 저장소를 설치, 빌드, 실행하기 전에
무실행으로 구조와 자동 실행 지점을 확인하는 것이다. 이후 확장은 저장소뿐
아니라 여러 설치 채널에서 같은 원칙을 적용하는 방향으로 검토한다.

원칙은 그대로 유지한다.

- 내려받기와 실행을 분리한다.
- 설치 스크립트, lifecycle hook, formula, manifest를 실행 전에 진단한다.
- 민감 후보는 기본 미열람으로 남긴다.
- 실행 또는 원문 포함은 별도 승인 게이트 뒤에만 허용한다.
- 결과는 안전 보증이 아니라 사전진단과 승인 판단 자료로 표시한다.

## 후보 설치 채널

### 1. 원격 설치 스크립트

대상 예:

- `curl ... | bash`
- `wget ... | sh`
- `install.sh`, `bootstrap.sh`, `setup.sh`

확장 방향:

- 파이프 실행 대신 파일로 저장한 뒤 검사하는 안전 흐름을 안내한다.
- 단일 스크립트 입력을 임시 검사 디렉터리로 감싸는 명령을 검토한다.
- 네트워크 URL, checksum, 저장 경로, 실행 후보를 별도 산출물로 남긴다.

검토 포인트:

- 스크립트가 다시 원격 코드를 내려받는지
- shell, Node, Python, Ruby, PowerShell 실행 토큰이 있는지
- sudo, chmod, curl, wget, eval, source 같은 실행 확대 지점이 있는지

### 2. npm, pnpm, yarn 패키지

대상 예:

- npm registry tarball
- `package.json` lifecycle script
- `preinstall`, `install`, `postinstall`, `prepare`

확장 방향:

- registry tarball 또는 lockfile 기반 패키지 아카이브를 실행 없이 검사한다.
- lifecycle script를 `gates.json.execution_review`와 연결한다.
- package manager별 integrity, resolved URL, tarball 해시를 별도 요약한다.

검토 포인트:

- package manager 명령 자체가 어떤 단계에서 script를 실행하는지 공식 동작
  확인이 필요하다.
- 기본 흐름은 install이 아니라 tarball 확보와 정적 검사여야 한다.
- 전이 의존성 전체 해석은 별도 단계로 분리한다.

### 3. Homebrew

대상 예:

- Formula
- Cask
- bottle
- install script

확장 방향:

- formula 파일과 연결된 source URL, checksum, patch, install block을 정적으로
  요약한다.
- bottle 바이너리 자체는 현재 도구가 안전성을 증명하지 못한다고 명시한다.
- checksum, 서명, 공식 tap 여부와 `git-scv`의 정적 진단을 병행한다.

검토 포인트:

- Ruby DSL 실행 없이 formula 정보를 파싱할 수 있는 범위
- source build와 bottle install의 위험 모델 차이
- postinstall 또는 caveats에 실행 안내가 숨어 있는지

### 4. Cargo 설치 경로

대상 예:

- `cargo install --git ...`
- `.crate` 패키지
- `build.rs`

확장 방향:

- git 저장소는 현재 `inspect` 또는 `snapshot` 흐름으로 먼저 검사한다.
- crates.io `.crate` 아카이브 검사는 별도 입력 타입으로 검토한다.
- `build.rs`와 proc-macro 의존성은 실행 전 검토 후보로 강조한다.

검토 포인트:

- 현재 도구는 Cargo 패키지를 설치하지 않는다.
- `build.rs` 존재는 실행 후보로 남기되 악성 단정은 하지 않는다.
- crates.io 메타데이터와 로컬 산출물의 경계를 분리한다.

### 5. 언어 버전 관리자와 런타임 설치 도구

대상 예:

- rustup
- nvm
- asdf
- pyenv
- rbenv

확장 방향:

- 설치 스크립트와 plugin repository를 실행 전에 검사하는 안내를 제공한다.
- 공식 설치 경로와 비공식 mirror 또는 fork를 구분해 기록한다.
- 사용자의 shell profile 변경 후보를 별도 발견사항으로 다룬다.

검토 포인트:

- PATH, shell rc 파일, profile 변경 여부
- 다시 내려받는 바이너리 또는 archive URL
- checksum 또는 signature 확인 경로

### 6. GitHub Release 바이너리와 압축 파일

대상 예:

- release asset zip/tarball
- prebuilt binary
- checksum file

확장 방향:

- 현재 `snapshot`의 HTTPS archive, checksum, 안전 압축 해제 경계를 확장한다.
- 바이너리 내용은 정적 구조 정보만 기록하고 안전성을 증명하지 않는다.
- checksum 파일과 release asset의 연결 검증을 별도 산출물로 검토한다.

검토 포인트:

- archive traversal, symlink, hardlink, 특수 파일 거부 정책 유지
- checksum 출처가 release와 독립 채널인지 여부
- 실행 파일 존재와 실행 권한 후보 표시

## 산출물 확장 후보

아래 산출물은 현재 계약에 포함하지 않는다. v0.3 이후 별도 사양으로 검토한다.

- `install_channel.json`: 입력 채널 종류와 원본 URL 또는 package coordinate
- `manager.json`: npm, brew, cargo 등 매니저별 정적 메타데이터
- `download.json`: 다운로드 URL, checksum, archive format, redaction 상태
- `lifecycle.json`: 설치 전 자동 실행 후보와 manager별 실행 단계

## v0.3 후보 작업

1. 단일 원격 스크립트 안전 검사 흐름 설계
2. npm tarball 무실행 검사 흐름 설계
3. Homebrew formula 정적 요약 가능 범위 조사
4. `.crate` 아카이브 검사 입력 타입 조사
5. GitHub Release asset checksum 검증 UX 조사

이 항목들은 현재 완료된 v0.3.3 빌딩플랜의 미완료가 아니다. 사용자가 다음
버전 범위를 선택할 때 후보로 비교한다.
