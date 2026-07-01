//! 증거 기록.
//!
//! id 는 E0001 부터 추가 순서대로, 재사용·결번 금지(0601). artifact에는
//! raw excerpt를 저장하지 않고 redacted excerpt와 label만 남긴다.

use crate::model::{Evidence, EvidenceArtifact, EvidenceKind, LineRange};
use crate::redaction::{redact_command_excerpt, SecretLikeLabel};

pub struct EvidenceStore {
    items: Vec<Evidence>,
}

pub struct EvidenceInput<'a> {
    pub path: &'a str,
    pub kind: EvidenceKind,
    pub lines: Option<LineRange>,
    pub summary: &'a str,
    pub json_pointer: Option<String>,
    pub signal_labels: Vec<String>,
    pub excerpt: Option<&'a str>,
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
    pub fn add(&mut self, input: EvidenceInput<'_>) -> String {
        let id = format!("E{:04}", self.items.len() + 1);
        let normalized_lines = if input.kind == EvidenceKind::ContentLine {
            input.lines
        } else {
            None
        };
        let (redacted_excerpt, redaction_applied, redaction_labels, signal_labels) =
            if input.kind == EvidenceKind::ContentLine {
                let redacted = input.excerpt.map(redact_command_excerpt);
                let redaction_labels = redacted
                    .as_ref()
                    .map(|value| {
                        value
                            .labels()
                            .iter()
                            .map(|label| label.as_str().into())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut signal_labels = input.signal_labels;
                if redacted
                    .as_ref()
                    .is_some_and(|value| value.labels().contains(&SecretLikeLabel::NetworkCommand))
                    && !signal_labels.iter().any(|label| label == "network-command")
                {
                    signal_labels.push("network-command".into());
                }
                if redacted.as_ref().is_some_and(|value| {
                    value
                        .labels()
                        .contains(&SecretLikeLabel::ShellExecutionToken)
                }) && !signal_labels
                    .iter()
                    .any(|label| label == "shell-execution-token")
                {
                    signal_labels.push("shell-execution-token".into());
                }
                signal_labels.sort();
                signal_labels.dedup();
                (
                    Some(redacted_command_placeholder(input.json_pointer.as_deref())),
                    redacted
                        .as_ref()
                        .is_some_and(|value| !value.labels().is_empty()),
                    redaction_labels,
                    signal_labels,
                )
            } else {
                (None, false, Vec::new(), input.signal_labels)
            };

        let json_pointer = if input.kind == EvidenceKind::ContentLine {
            input.json_pointer
        } else {
            None
        };

        self.items.push(Evidence {
            id: id.clone(),
            path: input.path.into(),
            kind: input.kind,
            json_pointer,
            lines: normalized_lines,
            summary: input.summary.into(),
            value_stored: false,
            redacted_excerpt,
            signal_labels,
            raw_excerpt_stored: false,
            redaction_applied,
            redaction_labels,
        });

        id
    }

    pub fn into_artifact(self, run_id: &str) -> EvidenceArtifact {
        EvidenceArtifact {
            schema_version: crate::model::SCHEMA_VERSION.into(),
            run_id: run_id.into(),
            evidence: self.items,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn redacted_command_placeholder(json_pointer: Option<&str>) -> String {
    let Some(pointer) = json_pointer else {
        return "<redacted-command>".into();
    };
    let key = pointer.rsplit('/').next().unwrap_or("command");
    format!("{key}: <redacted-command>")
}
