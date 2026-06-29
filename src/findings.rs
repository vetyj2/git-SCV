//! 발견사항 생성.
//!
//! 고정 문구 13종 표의 문장을 그대로 쓴다. id 는 F0001 부터, 규칙 번호 순
//! (D01→D13), 같은 규칙 안에서는 경로 사전순(T10 결정성).
//! `Finding::new` 가 빈 증거를 거부하므로(0606) 이 모듈은 증거를 먼저
//! 만들고 발견사항을 만든다.

use crate::errors::ScvError;
use crate::evidence::EvidenceStore;
use crate::model::{
    Category, Detection, EvidenceKind, Finding, LineRange, Priority, RuleId,
    LOW_CONFIDENCE_SENTENCE,
};

pub fn build(
    detections: &[Detection],
    store: &mut EvidenceStore,
) -> Result<Vec<Finding>, ScvError> {
    let mut findings = Vec::new();

    for rule in ordered_rules() {
        let mut items: Vec<&Detection> = detections
            .iter()
            .filter(|detection| detection.rule == rule)
            .collect();
        items.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.key.cmp(&right.key))
        });

        if items.is_empty() {
            continue;
        }

        match group_policy(rule) {
            GroupPolicy::Rule => {
                let evidence = items
                    .iter()
                    .map(|detection| add_evidence(store, detection))
                    .collect();
                push_finding(&mut findings, rule, &items, evidence)?;
            }
            GroupPolicy::Each => {
                for item in items {
                    let evidence = vec![add_evidence(store, item)];
                    push_finding(&mut findings, rule, &[item], evidence)?;
                }
            }
        }
    }

    Ok(findings)
}

/// findings.json 의 limitations 목록을 조립한다.
/// 공통 3문장(사양 0500 4절) + 상황별 문장 + 낮은 확신 문장(V06 조건).
pub fn limitations(
    git_dirty_unknown: bool,
    parse_failures: &[String],
    low_confidence: bool,
) -> Vec<String> {
    let mut items = vec![
        "무시 규칙(.gitignore 등)은 적용하지 않고 전 항목을 나열했다.".into(),
        "심볼릭 링크는 따라가지 않았다.".into(),
        "형태 감지는 이름 기반이며 파일 내용 분석은 package.json의 scripts에 한정되었다."
            .into(),
        "비밀값 후보 파일은 기본 검사에서 원문을 열지 않았으며, 별도 승인 전에는 내용 판단에서 제외되었다."
            .into(),
    ];

    if git_dirty_unknown {
        items.push("깃 변경 상태를 계산하지 못해 미커밋 변경 여부를 확인하지 않았다.".into());
    }

    items.extend(parse_failures.iter().cloned());

    if low_confidence {
        items.push(LOW_CONFIDENCE_SENTENCE.into());
    }

    items
}

#[derive(Clone, Copy)]
enum GroupPolicy {
    Rule,
    Each,
}

fn ordered_rules() -> [RuleId; 14] {
    [
        RuleId::D01,
        RuleId::D02,
        RuleId::D03,
        RuleId::D04,
        RuleId::D05,
        RuleId::D06,
        RuleId::D07,
        RuleId::D08,
        RuleId::D09,
        RuleId::D10,
        RuleId::D11,
        RuleId::D12,
        RuleId::D13,
        RuleId::D14,
    ]
}

fn group_policy(rule: RuleId) -> GroupPolicy {
    match rule {
        RuleId::D02 | RuleId::D05 | RuleId::D10 | RuleId::D11 | RuleId::D12 | RuleId::D13 => {
            GroupPolicy::Each
        }
        RuleId::D01
        | RuleId::D03
        | RuleId::D04
        | RuleId::D06
        | RuleId::D07
        | RuleId::D08
        | RuleId::D09
        | RuleId::D14 => GroupPolicy::Rule,
    }
}

fn add_evidence(store: &mut EvidenceStore, detection: &Detection) -> String {
    let kind = evidence_kind(detection.rule);
    let lines = detection.line.map(|line| LineRange {
        start: line,
        end: line,
    });
    let summary = evidence_summary(detection);
    store.add(
        &detection.path,
        kind,
        lines,
        &summary,
        json_pointer(detection),
        signal_labels(detection),
        detection.excerpt.as_deref(),
    )
}

fn json_pointer(detection: &Detection) -> Option<String> {
    if detection.rule == RuleId::D02 {
        return detection
            .key
            .as_deref()
            .map(|key| format!("/scripts/{}", escape_json_pointer(key)));
    }
    None
}

fn signal_labels(detection: &Detection) -> Vec<String> {
    match detection.rule {
        RuleId::D02 => vec![
            "lifecycle-script".into(),
            "execution-related-candidate".into(),
        ],
        _ => Vec::new(),
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn evidence_kind(rule: RuleId) -> EvidenceKind {
    match rule {
        RuleId::D02 => EvidenceKind::ContentLine,
        RuleId::D13 => EvidenceKind::SecretName,
        RuleId::D01
        | RuleId::D03
        | RuleId::D04
        | RuleId::D05
        | RuleId::D06
        | RuleId::D07
        | RuleId::D08
        | RuleId::D09
        | RuleId::D10
        | RuleId::D11
        | RuleId::D12
        | RuleId::D14 => EvidenceKind::FilePresence,
    }
}

fn evidence_summary(detection: &Detection) -> String {
    match detection.rule {
        RuleId::D01 => "자바스크립트 패키지 매니페스트가 존재함".into(),
        RuleId::D02 => format!(
            "package.json에 {} 스크립트가 정의됨",
            detection.key.as_deref().unwrap_or("알 수 없는")
        ),
        RuleId::D03 => "의존성 잠금 파일이 존재함".into(),
        RuleId::D04 => "러스트 매니페스트 파일이 존재함".into(),
        RuleId::D05 => "카고 빌드 스크립트가 존재함".into(),
        RuleId::D06 => "빌드 자동화 파일이 존재함".into(),
        RuleId::D07 => "컨테이너 정의 파일이 존재함".into(),
        RuleId::D08 => "지속 통합 워크플로 파일이 존재함".into(),
        RuleId::D09 => "셸 스크립트가 존재함".into(),
        RuleId::D10 => ".envrc 파일이 존재함".into(),
        RuleId::D11 => "편집기 자동 태스크 정의 파일이 존재함".into(),
        RuleId::D12 => "깃 훅 배포 디렉터리가 존재함".into(),
        RuleId::D13 => "비밀값으로 보이는 이름의 파일이 존재함 (내용 미열람)".into(),
        RuleId::D14 => "추가 생태계 매니페스트 또는 도구 설정 파일이 존재함".into(),
    }
}

fn push_finding(
    findings: &mut Vec<Finding>,
    rule: RuleId,
    detections: &[&Detection],
    evidence: Vec<String>,
) -> Result<(), ScvError> {
    let id = format!("F{:04}", findings.len() + 1);
    let text = finding_text(rule, detections);
    let finding = Finding::new(
        id,
        category(rule),
        priority(rule),
        text.summary,
        text.detail,
        text.limitation,
        evidence,
    )
    .map_err(|err| ScvError::Inspect(format!("findings: {err}")))?;
    findings.push(finding);
    Ok(())
}

struct FindingText {
    summary: String,
    detail: String,
    limitation: String,
}

fn finding_text(rule: RuleId, detections: &[&Detection]) -> FindingText {
    let paths: Vec<&str> = detections
        .iter()
        .map(|detection| detection.path.as_str())
        .collect();
    let count = paths.len();
    let path_list = format_paths(&paths);
    let first = detections[0];

    match rule {
        RuleId::D01 => FindingText {
            summary: format!("자바스크립트 패키지 매니페스트 {count}개가 있다."),
            detail: format!(
                "package.json이 발견되었다. 설치 시 의존성 해석과 스크립트 실행의 기준 파일이다. 경로: {path_list}."
            ),
            limitation: "매니페스트 존재 자체는 위험 판단의 근거가 아니다.".into(),
        },
        RuleId::D02 => {
            let key = first.key.as_deref().unwrap_or("알 수 없는");
            let line = first
                .line
                .map(|value| value.to_string())
                .unwrap_or_else(|| "확인 안 됨".into());
            FindingText {
                summary: format!("npm 설치 시 자동 실행되는 {key} 스크립트가 있다."),
                detail: format!(
                    "{} {line}행에 {key}가 정의되어 있어 npm install만으로 해당 명령이 실행될 수 있다.",
                    first.path
                ),
                limitation: "스크립트 명령의 실제 동작은 판단하지 않았다.".into(),
            }
        }
        RuleId::D03 => FindingText {
            summary: format!("의존성 잠금 파일 {count}개가 있다."),
            detail: format!("잠금 파일은 설치될 의존성 버전을 고정한다. 경로: {path_list}."),
            limitation: "잠금 파일이 가리키는 의존성 내용은 분석하지 않았다.".into(),
        },
        RuleId::D04 => FindingText {
            summary: format!("러스트 매니페스트 파일 {count}개가 있다."),
            detail: format!("Cargo.toml 또는 Cargo.lock이 발견되었다. 경로: {path_list}."),
            limitation: "의존성 내용은 분석하지 않았다.".into(),
        },
        RuleId::D05 => FindingText {
            summary: "카고 빌드 시 자동 실행되는 빌드 스크립트가 있다.".into(),
            detail: format!(
                "{}는 cargo build 시점에 컴파일되어 실행되는 build.rs다.",
                first.path
            ),
            limitation: "빌드 스크립트의 실제 동작은 판단하지 않았다.".into(),
        },
        RuleId::D06 => FindingText {
            summary: format!("빌드 자동화 파일 {count}개가 있다."),
            detail: format!("make 호출 시 사용되는 파일이다. 경로: {path_list}."),
            limitation: "내용은 분석하지 않았다.".into(),
        },
        RuleId::D07 => FindingText {
            summary: format!("컨테이너 정의 파일 {count}개가 있다."),
            detail: format!("컨테이너 빌드 또는 구성에 쓰이는 파일이다. 경로: {path_list}."),
            limitation: "내용은 분석하지 않았다.".into(),
        },
        RuleId::D08 => FindingText {
            summary: format!("지속 통합 워크플로 파일 {count}개가 있다."),
            detail: format!(
                ".github/workflows 아래 워크플로는 원격 지속 통합 환경에서 실행된다. 경로: {path_list}."
            ),
            limitation: "로컬 설치와 실행에는 직접 영향이 없으며 내용은 분석하지 않았다.".into(),
        },
        RuleId::D09 => FindingText {
            summary: format!("셸 스크립트 {count}개가 있다."),
            detail: format!(
                "셸 스크립트는 직접 실행되거나 다른 자동화에서 호출될 수 있다. 경로: {path_list}."
            ),
            limitation: "스크립트가 실제로 호출되는 경로는 추적하지 않았다.".into(),
        },
        RuleId::D10 => FindingText {
            summary: "디렉터리 진입만으로 실행될 수 있는 .envrc가 있다.".into(),
            detail: format!(
                "{}는 direnv 사용 환경에서 디렉터리 진입 시 자동 실행된다.",
                first.path
            ),
            limitation: "direnv 사용 여부와 스크립트 내용은 판단하지 않았다.".into(),
        },
        RuleId::D11 => FindingText {
            summary: "편집기 자동 태스크 정의 파일이 있다.".into(),
            detail: format!(
                "{}는 VS Code에서 폴더를 여는 시점에 자동 실행되도록 설정될 수 있는 tasks.json이다.",
                first.path
            ),
            limitation: "자동 실행 설정 여부는 내용을 열람하지 않아 확인하지 않았다.".into(),
        },
        RuleId::D12 => FindingText {
            summary: "깃 훅 배포 디렉터리(.husky)가 있다.".into(),
            detail: format!(
                "{}는 husky가 깃 훅을 설치하는 디렉터리로, 설치 후 깃 명령 시점에 스크립트가 실행될 수 있다.",
                first.path
            ),
            limitation: "훅 스크립트 내용은 분석하지 않았다.".into(),
        },
        RuleId::D13 => FindingText {
            summary: "비밀값 후보 또는 위장 스크립트일 수 있는 파일이 있다.".into(),
            detail: format!(
                "{}는 이름 패턴상 비밀값 후보이거나 별도 검토가 필요한 파일일 수 있다. 기본 검사에서는 내용을 열람하지 않았다.",
                first.path
            ),
            limitation: "내용 미열람 항목이므로 설치, 실행, 모델 입력 전 별도 확인이 필요하다.".into(),
        },
        RuleId::D14 => FindingText {
            summary: format!("추가 생태계 매니페스트 또는 도구 설정 파일 {count}개가 있다."),
            detail: format!(
                "Python, Go, Ruby, pre-commit 또는 유사 도구 표면이 감지됐다. 경로: {path_list}."
            ),
            limitation:
                "현재는 이름 기반 감지이며 각 생태계 매니페스트 본문을 완전 파싱하지 않는다."
                    .into(),
        },
    }
}

fn format_paths(paths: &[&str]) -> String {
    let visible: Vec<&str> = paths.iter().take(5).copied().collect();
    let mut text = visible.join(", ");
    if paths.len() > 5 {
        text.push_str(&format!(" 외 {}개", paths.len() - 5));
    }
    text
}

fn category(rule: RuleId) -> Category {
    match rule {
        RuleId::D01 | RuleId::D03 | RuleId::D04 | RuleId::D14 => Category::Manifest,
        RuleId::D02 | RuleId::D05 | RuleId::D10 | RuleId::D11 | RuleId::D12 => {
            Category::AutoExecHook
        }
        RuleId::D06 => Category::BuildAutomation,
        RuleId::D07 => Category::Container,
        RuleId::D08 => Category::CiAutomation,
        RuleId::D09 => Category::ShellScript,
        RuleId::D13 => Category::SecretCandidate,
    }
}

fn priority(rule: RuleId) -> Priority {
    match rule {
        RuleId::D01 | RuleId::D03 | RuleId::D04 | RuleId::D14 => Priority::Info,
        RuleId::D06 | RuleId::D07 | RuleId::D08 => Priority::Low,
        RuleId::D02 | RuleId::D05 | RuleId::D09 | RuleId::D11 | RuleId::D12 | RuleId::D13 => {
            Priority::Medium
        }
        RuleId::D10 => Priority::High,
    }
}
