//! 승인 게이트 산출물.
//!
//! 헤르메스나 다른 에이전트가 모델 입력 또는 설치·빌드·테스트·실행 승인
//! 요청 전에 제시해야 할 후보 목록을 감지 결과에서 조립한다.

use crate::model::{
    Detection, GateArtifact, GateItem, GatePrompt, RuleId, SensitiveArtifact, SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn build(
    detections: &[Detection],
    sensitive: &SensitiveArtifact,
    run_id: &str,
) -> GateArtifact {
    let sensitive_candidates = sensitive
        .candidates
        .iter()
        .map(|candidate| GateItem {
            path: candidate.path.clone(),
            rule: "D13".into(),
            reason: "비밀값 후보로 감지되어 기본 모델 입력에서 제외해야 한다.".into(),
        })
        .collect::<Vec<_>>();

    let automatic_execution_candidates = gate_items(detections, is_auto_execution_rule);
    let execution_related_candidates = gate_items(detections, is_execution_related_rule);

    let sensitive_paths = sensitive_candidates
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let execution_paths = combined_paths(
        &automatic_execution_candidates,
        &execution_related_candidates,
    );

    GateArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        sensitive_raw_review: GatePrompt {
            approval_required: !sensitive_paths.is_empty(),
            message: "민감 후보 원문을 모델 입력 또는 진단 입력에 포함하려면 1차 민감 후보 진단 승인과 2차 경로별 원문 포함 승인을 받아야 한다. 승인 질문에는 paths 목록을 그대로 보여준다.".into(),
            paths: sensitive_paths,
        },
        execution_review: GatePrompt {
            approval_required: !execution_paths.is_empty(),
            message: "설치, 빌드, 테스트, 실행, 훅, 컨테이너 명령을 실행하기 전에는 자동 실행 후보와 실행 관련 후보 paths 목록을 사용자에게 제시하고 별도 승인을 받아야 한다.".into(),
            paths: execution_paths,
        },
        sensitive_candidates,
        automatic_execution_candidates,
        execution_related_candidates,
        note: "이 산출물은 승인 질문을 만들기 위한 후보 목록이며 안전 보증이 아니다.".into(),
    }
}

fn gate_items(detections: &[Detection], include: fn(RuleId) -> bool) -> Vec<GateItem> {
    let mut items = BTreeMap::new();
    for detection in detections
        .iter()
        .filter(|detection| include(detection.rule))
    {
        let key = (
            rule_order(detection.rule),
            detection.path.clone(),
            detection.key.clone(),
        );
        items.entry(key).or_insert_with(|| GateItem {
            path: detection.path.clone(),
            rule: rule_label(detection.rule).into(),
            reason: reason(detection),
        });
    }
    items.into_values().collect()
}

fn combined_paths(left: &[GateItem], right: &[GateItem]) -> Vec<String> {
    left.iter()
        .chain(right.iter())
        .map(|item| item.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_auto_execution_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::D02 | RuleId::D05 | RuleId::D10 | RuleId::D11 | RuleId::D12
    )
}

fn is_execution_related_rule(rule: RuleId) -> bool {
    matches!(rule, RuleId::D06 | RuleId::D07 | RuleId::D08 | RuleId::D09)
}

fn reason(detection: &Detection) -> String {
    match detection.rule {
        RuleId::D02 => format!(
            "npm 설치 생명주기 스크립트가 정의되어 있다: {}",
            detection.key.as_deref().unwrap_or("알 수 없음")
        ),
        RuleId::D05 => "cargo build 시점에 build.rs가 컴파일되어 실행될 수 있다.".into(),
        RuleId::D10 => "direnv 환경에서 디렉터리 진입 시 .envrc가 실행될 수 있다.".into(),
        RuleId::D11 => "편집기 작업 정의가 폴더 열기나 작업 실행과 연결될 수 있다.".into(),
        RuleId::D12 => "깃 훅 배포 디렉터리가 설치 뒤 깃 명령과 연결될 수 있다.".into(),
        RuleId::D06 => "빌드 자동화 파일은 명령 실행 승인 전에 검토해야 한다.".into(),
        RuleId::D07 => "컨테이너 정의 파일은 빌드나 실행 승인 전에 검토해야 한다.".into(),
        RuleId::D08 => "지속 통합 워크플로는 원격 실행 경로를 만들 수 있다.".into(),
        RuleId::D09 => "셸 스크립트는 직접 실행되거나 자동화에서 호출될 수 있다.".into(),
        RuleId::D01 | RuleId::D03 | RuleId::D04 | RuleId::D13 => {
            "승인 게이트 대상 규칙이 아니다.".into()
        }
    }
}

fn rule_label(rule: RuleId) -> &'static str {
    match rule {
        RuleId::D01 => "D01",
        RuleId::D02 => "D02",
        RuleId::D03 => "D03",
        RuleId::D04 => "D04",
        RuleId::D05 => "D05",
        RuleId::D06 => "D06",
        RuleId::D07 => "D07",
        RuleId::D08 => "D08",
        RuleId::D09 => "D09",
        RuleId::D10 => "D10",
        RuleId::D11 => "D11",
        RuleId::D12 => "D12",
        RuleId::D13 => "D13",
    }
}

fn rule_order(rule: RuleId) -> u8 {
    match rule {
        RuleId::D01 => 1,
        RuleId::D02 => 2,
        RuleId::D03 => 3,
        RuleId::D04 => 4,
        RuleId::D05 => 5,
        RuleId::D06 => 6,
        RuleId::D07 => 7,
        RuleId::D08 => 8,
        RuleId::D09 => 9,
        RuleId::D10 => 10,
        RuleId::D11 => 11,
        RuleId::D12 => 12,
        RuleId::D13 => 13,
    }
}
