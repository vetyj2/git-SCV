//! 산출물 기록.
//!
//! 쓰기 순서 고정: source → inventory → coverage → evidence → findings →
//! sectors → sensitive → gates → slices → review → report.md. run.json 은 별도 함수로, 항상 마지막에(0202).
//! 모든 쓰기 직전에 safety::assert_inside 를 호출한다(1105).
//! JSON 은 to_string_pretty + 끝 줄바꿈 하나.

use crate::errors::ScvError;
use crate::model::{RunArtifact, RunData};
use crate::safety;
use serde::Serialize;
use std::fs;
use std::path::Path;

pub fn write_all(out: &Path, data: &RunData) -> Result<(), ScvError> {
    write_json(out, "source.json", &data.source)?;
    write_json(out, "inventory.json", &data.inventory)?;
    write_json(out, "coverage.json", &data.coverage)?;
    write_json(out, "evidence.json", &data.evidence)?;
    write_json(out, "findings.json", &data.findings)?;
    write_json(out, "sectors.json", &data.sectors)?;
    write_json(out, "sensitive.json", &data.sensitive)?;
    write_json(out, "gates.json", &data.gates)?;
    write_json(out, "slices.json", &data.slices)?;
    write_json(out, "review.json", &data.review)?;
    write_text(out, "report.md", &data.report_md)
}

/// run.json 만 따로 — 단계 실패 시에도 호출되어야 한다(0202, 0203).
pub fn write_run_json(out: &Path, run: &RunArtifact) -> Result<(), ScvError> {
    write_json(out, "run.json", run)
}

fn write_json<T: Serialize>(out: &Path, name: &str, value: &T) -> Result<(), ScvError> {
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|err| ScvError::Inspect(format!("artifacts: JSON 직렬화 실패: {name}: {err}")))?;
    text.push('\n');
    write_text(out, name, &text)
}

fn write_text(out: &Path, name: &str, text: &str) -> Result<(), ScvError> {
    let target = out.join(name);
    safety::assert_inside(out, &target)?;
    fs::write(&target, text).map_err(|err| {
        ScvError::Inspect(format!(
            "artifacts: 산출물을 쓰지 못했다: {}: {err}",
            target.display()
        ))
    })
}
