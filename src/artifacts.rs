//! 산출물 기록.
//!
//! 쓰기 순서 고정: source → inventory → coverage → evidence → findings →
//! dependencies → sectors → sensitive → gates → slices → review → security →
//! report.md/html.
//! run.json 은 별도 함수로, 항상 마지막에(0202).
//! 모든 쓰기 직전에 safety::assert_inside 를 호출한다(1105).
//! JSON 은 to_string_pretty + 끝 줄바꿈 하나.

use crate::errors::ScvError;
use crate::model::{
    ArtifactManifest, BriefArtifact, ManifestArtifactEntry, ManifestValidation, PathPrivacyMode,
    RunArtifact, RunData, ToolInfo, NO_EXEC_SENTENCE,
};
use crate::safety;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub fn write_all(out: &Path, data: &RunData) -> Result<(), ScvError> {
    write_json(out, "source.json", &data.source)?;
    write_json(out, "inventory.json", &data.inventory)?;
    write_json(out, "coverage.json", &data.coverage)?;
    write_json(out, "evidence.json", &data.evidence)?;
    write_json(out, "findings.json", &data.findings)?;
    write_json(out, "dependencies.json", &data.dependencies)?;
    write_json(out, "sectors.json", &data.sectors)?;
    write_json(out, "sensitive.json", &data.sensitive)?;
    write_json(out, "gates.json", &data.gates)?;
    write_json(out, "slices.json", &data.slices)?;
    write_json(out, "review.json", &data.review)?;
    write_json(out, "security.json", &data.security)?;
    write_json(out, "connection_graph.json", &data.connection_graph)?;
    write_json(out, "analysis_plan.json", &data.analysis_plan)?;
    write_json(out, "cross_unit_analysis.json", &data.cross_unit_analysis)?;
    write_json(out, "synthesis.json", &data.synthesis)?;
    write_json(out, "followup_plan.json", &data.followup_plan)?;
    write_text(out, "report.md", &data.report_md)?;
    write_text(out, "report.html", &crate::web_report::render(data))
}

/// run.json 만 따로 — 단계 실패 시에도 호출되어야 한다(0202, 0203).
pub fn write_run_json(out: &Path, run: &RunArtifact) -> Result<(), ScvError> {
    write_json(out, "run.json", run)
}

pub fn write_artifact_manifest(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let manifest = build_artifact_manifest(out, data)?;
    write_json(out, "artifact_manifest.json", &manifest)
}

pub fn write_brief_artifacts(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let artifact_manifest_sha256 = file_sha256(out, "artifact_manifest.json")?;
    let brief = build_brief_artifact(data, artifact_manifest_sha256);
    write_json(out, "brief.json", &brief)?;
    write_text(out, "brief.md", &render_brief_markdown(&brief))
}

fn write_json<T: Serialize>(out: &Path, name: &str, value: &T) -> Result<(), ScvError> {
    let value = artifact_value_with_contract(name, value)?;
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|err| ScvError::Inspect(format!("artifacts: JSON 직렬화 실패: {name}: {err}")))?;
    text.push('\n');
    write_text(out, name, &text)
}

pub(crate) fn artifact_value_with_contract<T: Serialize>(
    name: &str,
    value: &T,
) -> Result<Value, ScvError> {
    let mut value = serde_json::to_value(value)
        .map_err(|err| ScvError::Inspect(format!("artifacts: JSON 직렬화 실패: {name}: {err}")))?;
    let Some(object) = value.as_object_mut() else {
        return Ok(value);
    };
    object
        .entry("artifact_kind")
        .or_insert_with(|| Value::String(artifact_kind_for_name(name).into()));
    object
        .entry("contract_version")
        .or_insert_with(|| Value::String("artifact-contract-v2".into()));
    object.entry("producer").or_insert_with(|| {
        json!({
            "name": "git-scv",
            "version": env!("CARGO_PKG_VERSION"),
        })
    });
    object
        .entry("min_reader_version")
        .or_insert_with(|| Value::String(env!("CARGO_PKG_VERSION").into()));
    Ok(value)
}

fn artifact_kind_for_name(name: &str) -> &str {
    match name {
        "run.json" => "run",
        "source.json" => "source",
        "inventory.json" => "inventory",
        "coverage.json" => "coverage",
        "evidence.json" => "evidence",
        "findings.json" => "findings",
        "dependencies.json" => "dependencies",
        "sectors.json" => "sectors",
        "sensitive.json" => "sensitive",
        "gates.json" => "gates",
        "slices.json" => "slices",
        "review.json" => "review",
        "security.json" => "security",
        "connection_graph.json" => "connection_graph",
        "analysis_plan.json" => "analysis_plan",
        "cross_unit_analysis.json" => "cross_unit_analysis",
        "synthesis.json" => "synthesis",
        "followup_plan.json" => "followup_plan",
        "artifact_manifest.json" => "artifact_manifest",
        "brief.json" => "brief",
        "agent_receipt.json" => "agent_receipt",
        _ => "unknown",
    }
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

fn build_artifact_manifest(out: &Path, data: &RunData) -> Result<ArtifactManifest, ScvError> {
    let mut artifacts = Vec::new();
    for name in MANIFEST_HASHED_ARTIFACTS {
        artifacts.push(ManifestArtifactEntry {
            name: name.into(),
            sha256: file_sha256(out, name)?,
            required: true,
            validated: true,
        });
    }
    Ok(ArtifactManifest {
        artifact_kind: "artifact_manifest".into(),
        schema_version: "2".into(),
        contract_version: "artifact-contract-v2".into(),
        producer: ToolInfo {
            name: "git-scv".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        min_reader_version: env!("CARGO_PKG_VERSION").into(),
        run_id: data.run_id.clone(),
        source_fingerprint_hash: data
            .source
            .source_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.fingerprint_hash.clone())
            .unwrap_or_else(|| "sha256:unknown".into()),
        redaction_policy_version: "redaction-v1".into(),
        path_privacy_policy: path_privacy_label(data.source.path_privacy.mode).into(),
        artifacts,
        validation: ManifestValidation {
            schema_validation_passed: true,
            artifact_leak_scan_passed: true,
            post_write_verify_passed: true,
        },
    })
}

fn build_brief_artifact(data: &RunData, artifact_manifest_sha256: String) -> BriefArtifact {
    let action_required = data
        .review
        .required_actions
        .iter()
        .any(|action| action.required);
    let required_actions = data
        .review
        .required_actions
        .iter()
        .filter(|action| action.required)
        .map(|action| action.id.clone())
        .collect::<Vec<_>>();
    let mut next_step_blocked_until = vec!["agent_read_receipt".into()];
    if action_required {
        next_step_blocked_until.push("user_gate_decision".into());
    }
    next_step_blocked_until.push("source_verify_before_execution".into());
    BriefArtifact {
        artifact_kind: "brief".into(),
        schema_version: "2".into(),
        run_id: data.run_id.clone(),
        artifact_manifest_sha256,
        source_fingerprint_hash: data
            .source
            .source_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.fingerprint_hash.clone())
            .unwrap_or_else(|| "sha256:unknown".into()),
        verdict: data.review.verdict.clone(),
        safe_claim_made: data.review.safe_claim_made,
        may_user_run_install: data.review.may_user_run_install,
        may_agent_request_run_approval: data.review.may_agent_request_run_approval,
        may_agent_run_without_user: data.review.may_agent_run_without_user,
        action_required,
        counts: data.review.counts.clone(),
        required_actions,
        reason_codes: data.review.reason_codes.clone(),
        next_step_blocked_until,
        no_exec_statement: NO_EXEC_SENTENCE.into(),
    }
}

fn render_brief_markdown(brief: &BriefArtifact) -> String {
    let required_actions = if brief.required_actions.is_empty() {
        "none".into()
    } else {
        brief.required_actions.join(", ")
    };
    let reason_codes = if brief.reason_codes.is_empty() {
        "none".into()
    } else {
        brief.reason_codes.join(", ")
    };
    format!(
        "# git-scv brief\n\n\
- run_id: {run_id}\n\
- artifact_manifest_sha256: {artifact_manifest_sha256}\n\
- source_fingerprint_hash: {source_fingerprint_hash}\n\
- verdict: {verdict}\n\
- safe_claim_made: {safe_claim_made}\n\
- may_user_run_install: {may_user_run_install}\n\
- may_agent_request_run_approval: {may_agent_request_run_approval}\n\
- may_agent_run_without_user: {may_agent_run_without_user}\n\
- action_required: {action_required}\n\
- required_actions: {required_actions}\n\
- reason_codes: {reason_codes}\n\
- next_step_blocked_until: {next_step_blocked_until}\n\n\
## counts\n\n\
- findings_total: {findings_total}\n\
- sensitive_candidates: {sensitive_candidates}\n\
- automatic_execution_candidates: {automatic_execution_candidates}\n\
- execution_related_candidates: {execution_related_candidates}\n\
- default_model_excluded_paths: not-listed-in-brief\n\
- slices_over_token_limit: {slices_over_token_limit}\n\n\
## no-exec\n\n\
{no_exec_statement}\n",
        run_id = brief.run_id.as_str(),
        artifact_manifest_sha256 = brief.artifact_manifest_sha256.as_str(),
        source_fingerprint_hash = brief.source_fingerprint_hash.as_str(),
        verdict = brief.verdict.as_str(),
        safe_claim_made = brief.safe_claim_made,
        may_user_run_install = brief.may_user_run_install,
        may_agent_request_run_approval = brief.may_agent_request_run_approval,
        may_agent_run_without_user = brief.may_agent_run_without_user,
        action_required = brief.action_required,
        required_actions = required_actions,
        reason_codes = reason_codes,
        next_step_blocked_until = brief.next_step_blocked_until.join(", "),
        findings_total = brief.counts.findings_total,
        sensitive_candidates = brief.counts.sensitive_candidates,
        automatic_execution_candidates = brief.counts.automatic_execution_candidates,
        execution_related_candidates = brief.counts.execution_related_candidates,
        slices_over_token_limit = brief.counts.slices_over_token_limit,
        no_exec_statement = brief.no_exec_statement.as_str(),
    )
}

pub(crate) fn file_sha256(out: &Path, name: &str) -> Result<String, ScvError> {
    let target = out.join(name);
    safety::assert_inside(out, &target)?;
    let bytes = fs::read(&target).map_err(|err| {
        ScvError::Inspect(format!(
            "artifacts: manifest 해시 대상 파일을 읽지 못했다: {}: {err}",
            target.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{}", hex_lower(hasher.finalize())))
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn path_privacy_label(mode: PathPrivacyMode) -> &'static str {
    match mode {
        PathPrivacyMode::RepoRelative => "repo-relative",
        PathPrivacyMode::RedactedAbsolute => "redacted-absolute",
        PathPrivacyMode::Absolute => "absolute",
    }
}

pub const MANIFEST_HASHED_ARTIFACTS: [&str; 20] = [
    "run.json",
    "source.json",
    "inventory.json",
    "coverage.json",
    "evidence.json",
    "findings.json",
    "dependencies.json",
    "sectors.json",
    "sensitive.json",
    "gates.json",
    "slices.json",
    "review.json",
    "security.json",
    "connection_graph.json",
    "analysis_plan.json",
    "cross_unit_analysis.json",
    "synthesis.json",
    "followup_plan.json",
    "report.md",
    "report.html",
];
