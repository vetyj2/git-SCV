//! 의존성 요약 산출물.
//!
//! 현재는 detect 단계에서 이미 읽은 package.json 결과만 사용한다. 의존성
//! 버전·URL 원문은 토큰이 섞일 수 있으므로 저장하지 않고 출처 종류만 남긴다.

use crate::model::{DependencyArtifact, DependencyManifest, DetectOutcome, SCHEMA_VERSION};

pub fn build(outcome: &DetectOutcome, run_id: &str) -> DependencyArtifact {
    DependencyArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        manifests: outcome.dependency_manifests.clone(),
        limitations: limitations(&outcome.dependency_manifests),
        note: "의존성 요약은 package.json 이름과 출처 종류만 기록하며 버전·URL 원문은 저장하지 않는다.".into(),
    }
}

fn limitations(manifests: &[DependencyManifest]) -> Vec<String> {
    let mut items = vec![
        "현재 의존성 요약은 npm package.json에 한정된다.".into(),
        "버전 범위, URL, git 주소, 로컬 경로 원문은 저장하지 않았다.".into(),
        "설치될 전이 의존성 그래프는 해석하지 않았다.".into(),
    ];
    if manifests.is_empty() {
        items.push("분석 가능한 package.json 의존성 매니페스트가 없었다.".into());
    }
    items
}
