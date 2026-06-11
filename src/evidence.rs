//! 증거 기록.
//!
//! id 는 E0001 부터 추가 순서대로, 재사용·결번 금지(0601).
//! excerpt 는 최대 200자(문자 기준), kind=SecretName 이면 항상 None(0604).

use crate::model::{Evidence, EvidenceArtifact, EvidenceKind, LineRange};

pub struct EvidenceStore {
    items: Vec<Evidence>,
}

impl Default for EvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceStore {
    pub fn new() -> Self {
        EvidenceStore { items: Vec::new() }
    }

    /// 추가하고 부여된 id("E0001"…)를 돌려준다.
    pub fn add(
        &mut self,
        path: &str,
        kind: EvidenceKind,
        lines: Option<LineRange>,
        summary: &str,
        excerpt: Option<&str>,
    ) -> String {
        let _ = (path, kind, lines, summary, excerpt);
        todo!("evidence generation is not implemented yet")
    }

    pub fn into_artifact(self, run_id: &str) -> EvidenceArtifact {
        let _ = run_id;
        todo!("evidence artifact generation is not implemented yet")
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
