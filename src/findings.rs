//! 발견사항 생성.
//!
//! 고정 문구 13종 표의 문장을 그대로 쓴다. id 는 F0001 부터, 규칙 번호 순
//! (D01→D13), 같은 규칙 안에서는 경로 사전순(T10 결정성).
//! `Finding::new` 가 빈 증거를 거부하므로(0606) 이 모듈은 증거를 먼저
//! 만들고 발견사항을 만든다.

use crate::errors::ScvError;
use crate::evidence::EvidenceStore;
use crate::model::{Detection, Finding};

pub fn build(
    detections: &[Detection],
    store: &mut EvidenceStore,
) -> Result<Vec<Finding>, ScvError> {
    let _ = (detections, store);
    todo!("findings generation is not implemented yet")
}

/// findings.json 의 limitations 목록을 조립한다.
/// 공통 3문장(사양 0500 4절) + 상황별 문장 + 낮은 확신 문장(V06 조건).
pub fn limitations(
    git_dirty_unknown: bool,
    parse_failures: &[String],
    low_confidence: bool,
) -> Vec<String> {
    let _ = (git_dirty_unknown, parse_failures, low_confidence);
    todo!("limitations generation is not implemented yet")
}
