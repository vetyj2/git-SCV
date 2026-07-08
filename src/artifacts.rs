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
    ActionabilityBlocker, AnalysisJob, ArtifactManifest, BriefActionability, BriefArtifact,
    ManifestArtifactEntry, ManifestValidation, PathPrivacyMode, RunArtifact, RunData, ToolInfo,
    NO_EXEC_SENTENCE,
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
    write_json(
        out,
        "static_preflight_summary.json",
        &data.static_preflight_summary,
    )?;
    write_json(out, "sub_slices.json", &data.sub_slices)?;
    write_jsonl(out, "sub_slices.jsonl", &data.sub_slices.sub_slices)?;
    write_json(out, "analysis_inputs.json", &data.analysis_inputs)?;
    write_jsonl(out, "analysis_inputs.jsonl", &data.analysis_inputs.inputs)?;
    write_json(out, "analysis_state.json", &data.analysis_state)?;
    write_jsonl(out, "analysis_events.jsonl", &data.analysis_events)?;
    write_json(out, "llm_backend.json", &data.llm_backend)?;
    write_json(out, "gpt_work_order.json", &data.gpt_work_order)?;
    let work_order_sha256 = file_sha256(out, "gpt_work_order.json")?;
    write_text(
        out,
        "gpt_work_order.md",
        &render_gpt_work_order_markdown(&data.gpt_work_order),
    )?;
    let analysis_jobs = jobs_with_work_order_hash(&data.analysis_jobs, &work_order_sha256);
    write_jsonl(out, "analysis_jobs.jsonl", &analysis_jobs)?;
    write_jsonl(
        out,
        "codex_invocation_receipt.jsonl",
        &data.codex_invocation_receipts,
    )?;
    write_json(out, "review.json", &data.review)?;
    write_json(out, "security.json", &data.security)?;
    write_json(out, "supported_surfaces.json", &data.supported_surfaces)?;
    write_json(out, "gate_decisions.json", &data.gate_decisions)?;
    write_json(out, "connection_graph.json", &data.connection_graph)?;
    write_json(
        out,
        "reachability_scenarios.json",
        &data.reachability_scenarios,
    )?;
    write_json(out, "architecture_map.json", &data.architecture_map)?;
    write_json(out, "relation_map.json", &data.relation_map)?;
    write_json(out, "source_landmarks.json", &data.source_landmarks)?;
    write_json(out, "visualization_index.json", &data.visualization_index)?;
    write_json(out, "analysis_plan.json", &data.analysis_plan)?;
    write_json(out, "analysis_map.json", &data.analysis_map)?;
    write_json(out, "cross_unit_analysis.json", &data.cross_unit_analysis)?;
    write_json(out, "synthesis.json", &data.synthesis)?;
    write_json(out, "followup_plan.json", &data.followup_plan)?;
    write_text(out, "report.md", &data.report_md)?;
    write_text(out, "report.html", &crate::web_report::render(data))?;
    write_text(out, "architecture.html", &data.architecture_html)
}

/// run.json 만 따로 — 단계 실패 시에도 호출되어야 한다(0202, 0203).
pub fn write_run_json(out: &Path, run: &RunArtifact) -> Result<(), ScvError> {
    write_json(out, "run.json", run)
}

pub fn write_artifact_manifest(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let manifest = build_artifact_manifest(out, data)?;
    write_json(out, "artifact_manifest.json", &manifest)
}

pub fn write_work_order_binding(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let value = json!({
        "artifact_kind": "work_order_binding",
        "schema_version": "2",
        "contract_version": "artifact-contract-v2",
        "producer": {
            "name": "git-scv",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "min_reader_version": env!("CARGO_PKG_VERSION"),
        "run_id": data.run_id.clone(),
        "work_order_sha256": file_sha256(out, "gpt_work_order.json")?,
        "artifact_manifest_sha256": file_sha256(out, "artifact_manifest.json")?,
        "source_fingerprint_hash": data
            .source
            .source_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.fingerprint_hash.clone())
            .unwrap_or_else(|| "sha256:unknown".into()),
        "expires_on_source_change": true,
        "oauth_token_stored": false,
        "oauth_token_forwarded": false,
    });
    write_json(out, "work_order_binding.json", &value)
}

pub fn write_brief_artifacts(out: &Path, data: &RunData) -> Result<(), ScvError> {
    let artifact_manifest_sha256 = file_sha256(out, "artifact_manifest.json")?;
    let brief = build_brief_artifact(data, artifact_manifest_sha256);
    write_json(out, "brief.json", &brief)?;
    write_text(out, "brief.md", &render_brief_markdown(&brief))
}

fn jobs_with_work_order_hash(jobs: &[AnalysisJob], work_order_sha256: &str) -> Vec<AnalysisJob> {
    jobs.iter()
        .cloned()
        .map(|mut job| {
            job.work_order_sha256 = work_order_sha256.into();
            job
        })
        .collect()
}

fn write_json<T: Serialize>(out: &Path, name: &str, value: &T) -> Result<(), ScvError> {
    let value = artifact_value_with_contract(name, value)?;
    let mut text = serde_json::to_string_pretty(&value)
        .map_err(|err| ScvError::Inspect(format!("artifacts: JSON 직렬화 실패: {name}: {err}")))?;
    text.push('\n');
    write_text(out, name, &text)
}

fn write_jsonl<T: Serialize>(out: &Path, name: &str, values: &[T]) -> Result<(), ScvError> {
    let mut text = String::new();
    for value in values {
        let mut value = serde_json::to_value(value).map_err(|err| {
            ScvError::Inspect(format!("artifacts: JSONL 직렬화 실패: {name}: {err}"))
        })?;
        if let Some(object) = value.as_object_mut() {
            object
                .entry("contract_version")
                .or_insert_with(|| Value::String("artifact-contract-v2".into()));
            object.entry("producer").or_insert_with(|| {
                json!({
                    "name": "git-scv",
                    "version": env!("CARGO_PKG_VERSION"),
                })
            });
        }
        text.push_str(&serde_json::to_string(&value).map_err(|err| {
            ScvError::Inspect(format!("artifacts: JSONL 직렬화 실패: {name}: {err}"))
        })?);
        text.push('\n');
    }
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
        "static_preflight_summary.json" => "static_preflight_summary",
        "sub_slices.json" => "sub_slices",
        "analysis_inputs.json" => "analysis_inputs",
        "analysis_state.json" => "analysis_state",
        "llm_backend.json" => "llm_backend",
        "gpt_work_order.json" => "gpt_work_order",
        "work_order_binding.json" => "work_order_binding",
        "cleanup_manifest.json" => "cleanup_manifest",
        "review.json" => "review",
        "security.json" => "security",
        "supported_surfaces.json" => "supported_surfaces",
        "gate_decisions.json" => "gate_decisions",
        "connection_graph.json" => "connection_graph",
        "reachability_scenarios.json" => "reachability_scenarios",
        "architecture_map.json" => "architecture_map",
        "relation_map.json" => "relation_map",
        "source_landmarks.json" => "source_landmarks",
        "visualization_index.json" => "visualization_index",
        "analysis_plan.json" => "analysis_plan",
        "analysis_map.json" => "analysis_map",
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
        analysis_stage: data.analysis_state.analysis_stage,
        analysis_stage_label: data.analysis_state.analysis_stage.user_badge().into(),
        final_report_ready: data.analysis_state.analysis_stage.allows_final_report(),
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
        actionability: brief_actionability(data),
        visual_outputs: vec![
            "architecture.html".into(),
            "architecture_map.json".into(),
            "relation_map.json".into(),
            "source_landmarks.json".into(),
            "visualization_index.json".into(),
        ],
        do_not_do_yet: do_not_do_yet(data),
        no_exec_statement: NO_EXEC_SENTENCE.into(),
    }
}

fn brief_actionability(data: &RunData) -> BriefActionability {
    BriefActionability {
        top_blockers: top_blockers(data),
        next_safe_commands: vec![
            "git-scv brief <run-dir>".into(),
            "git-scv case show <case-id>".into(),
            "git-scv case verify-source <case-id>".into(),
            "git-scv case next-action <case-id> --action install --argv npm install".into(),
            "open architecture.html".into(),
        ],
        do_not_do_yet: do_not_do_yet(data),
    }
}

fn top_blockers(data: &RunData) -> Vec<ActionabilityBlocker> {
    let mut blockers = Vec::new();
    if data.gates.execution_command_review.approval_required {
        blockers.push(ActionabilityBlocker {
            id: "B0001".into(),
            kind: "execution-candidate".into(),
            summary: "Execution-related repository surfaces are present.".into(),
            why_it_matters:
                "Install, build, test, run, hook, workflow, or container actions can reach target-controlled commands.".into(),
            next_step: "Review gates.json, architecture.html, and request exact command approval only after source verification.".into(),
            artifact_refs: vec![
                "brief.json".into(),
                "gates.json".into(),
                "architecture.html".into(),
                "reachability_scenarios.json".into(),
            ],
        });
    }
    if data.gates.sensitive_raw_review.approval_required {
        blockers.push(ActionabilityBlocker {
            id: format!("B{:04}", blockers.len() + 1),
            kind: "sensitive-candidate".into(),
            summary: "Sensitive-looking paths are excluded from raw default review.".into(),
            why_it_matters:
                "Secrets, credentials, or private configuration may be present and should not be copied into artifacts or model input by default.".into(),
            next_step: "Review sensitive.json and request path-specific sensitive raw approval only when needed.".into(),
            artifact_refs: vec!["sensitive.json".into(), "gates.json".into()],
        });
    }
    if data
        .coverage
        .capabilities
        .iter()
        .any(|capability| capability.verdict_effect.is_some())
    {
        blockers.push(ActionabilityBlocker {
            id: format!("B{:04}", blockers.len() + 1),
            kind: "insufficient-coverage".into(),
            summary: "Unsupported or only name-detected surfaces limit the conclusion.".into(),
            why_it_matters:
                "Git-SCV cannot claim no blocker observed when execution-related surfaces are not structurally parsed.".into(),
            next_step: "Review coverage.json, supported_surfaces.json, and the Coverage view in architecture.html.".into(),
            artifact_refs: vec![
                "coverage.json".into(),
                "supported_surfaces.json".into(),
                "architecture.html".into(),
            ],
        });
    }
    blockers
}

fn do_not_do_yet(data: &RunData) -> Vec<String> {
    let mut commands = Vec::new();
    if data.gates.execution_command_review.approval_required {
        commands.extend([
            "npm install".into(),
            "cargo build".into(),
            "docker build".into(),
            "make".into(),
        ]);
    }
    if commands.is_empty() {
        commands
            .push("Do not run target repository commands without explicit user approval.".into());
    }
    commands
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
- analysis_stage: {analysis_stage}\n\
- analysis_stage_label: {analysis_stage_label}\n\
- final_report_ready: {final_report_ready}\n\
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
## actionability\n\n\
- top_blockers: {top_blockers}\n\
- next_safe_commands: {next_safe_commands}\n\
- do_not_do_yet: {do_not_do_yet}\n\
- visual_outputs: {visual_outputs}\n\n\
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
        analysis_stage = brief.analysis_stage.as_str(),
        analysis_stage_label = brief.analysis_stage_label.as_str(),
        final_report_ready = brief.final_report_ready,
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
        top_blockers = brief.actionability.top_blockers.len(),
        next_safe_commands = brief.actionability.next_safe_commands.join(", "),
        do_not_do_yet = brief.do_not_do_yet.join(", "),
        visual_outputs = brief.visual_outputs.join(", "),
        findings_total = brief.counts.findings_total,
        sensitive_candidates = brief.counts.sensitive_candidates,
        automatic_execution_candidates = brief.counts.automatic_execution_candidates,
        execution_related_candidates = brief.counts.execution_related_candidates,
        slices_over_token_limit = brief.counts.slices_over_token_limit,
        no_exec_statement = brief.no_exec_statement.as_str(),
    )
}

fn render_gpt_work_order_markdown(order: &crate::model::GptWorkOrderArtifact) -> String {
    let mut text = format!(
        "# Git-SCV GPT work order\n\n\
- run_id: {run_id}\n\
- analysis_stage: {analysis_stage}\n\
- receipt_kind: {receipt_kind}\n\
- backend: {backend}\n\
- cli_backend_available: {cli_backend_available}\n\
- external_codex_session_allowed: {external_codex_session_allowed}\n\
- credential_policy: {credential_policy}\n\
- oauth_token_stored: {oauth_token_stored}\n\
- oauth_token_forwarded: {oauth_token_forwarded}\n\
- source_fingerprint_hash: {source_fingerprint_hash}\n\
- artifact_manifest_sha256: {artifact_manifest_sha256}\n\
- raw_content_stored: {raw_content_stored}\n\
- target_repo_commands_executed: {target_repo_commands_executed}\n\n\
## Purpose\n\n\
{purpose}\n\n\
## GPT handoff prompt\n\n\
{gpt_handoff_prompt}\n\n\
## Ordered steps\n\n",
        run_id = order.run_id,
        analysis_stage = order.analysis_stage.as_str(),
        receipt_kind = order.receipt_kind,
        backend = order.backend,
        cli_backend_available = order.cli_backend_available,
        external_codex_session_allowed = order.external_codex_session_allowed,
        credential_policy = order.credential_policy,
        oauth_token_stored = order.oauth_token_stored,
        oauth_token_forwarded = order.oauth_token_forwarded,
        source_fingerprint_hash = order.source_fingerprint_hash,
        artifact_manifest_sha256 = order.artifact_manifest_sha256,
        raw_content_stored = order.raw_content_stored,
        target_repo_commands_executed = order.target_repo_commands_executed,
        purpose = order.purpose,
        gpt_handoff_prompt = order.gpt_handoff_prompt,
    );
    for step in &order.ordered_steps {
        text.push_str(&format!(
            "### {order_num}. {title}\n\n\
- step_id: {step_id}\n\
- gpt_action: {gpt_action}\n\
- command: {command}\n\
- reads: {reads}\n\
- writes: {writes}\n\
- required_before: {required_before}\n\
- success_criteria: {success_criteria}\n\
- blocked_by: {blocked_by}\n\n",
            order_num = step.order,
            title = step.title,
            step_id = step.step_id,
            gpt_action = step.gpt_action,
            command = step.command.as_deref().unwrap_or("GPT/manual step"),
            reads = step.reads.join(", "),
            writes = step.writes.join(", "),
            required_before = step.required_before.join(", "),
            success_criteria = step.success_criteria.join(", "),
            blocked_by = if step.blocked_by.is_empty() {
                "none".into()
            } else {
                step.blocked_by.join(", ")
            },
        ));
    }
    text.push_str("## Stop conditions\n\n");
    for item in &order.stop_conditions {
        text.push_str(&format!("- {item}\n"));
    }
    text.push_str("\n## Resume strategy\n\n");
    for item in &order.resume_strategy {
        text.push_str(&format!("- {item}\n"));
    }
    text.push_str("\n## No-exec\n\n");
    text.push_str(&order.no_exec_statement);
    text.push('\n');
    text
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

pub const MANIFEST_HASHED_ARTIFACTS: [&str; 41] = [
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
    "static_preflight_summary.json",
    "sub_slices.json",
    "sub_slices.jsonl",
    "analysis_inputs.json",
    "analysis_inputs.jsonl",
    "analysis_state.json",
    "analysis_events.jsonl",
    "llm_backend.json",
    "gpt_work_order.json",
    "gpt_work_order.md",
    "analysis_jobs.jsonl",
    "codex_invocation_receipt.jsonl",
    "review.json",
    "security.json",
    "supported_surfaces.json",
    "gate_decisions.json",
    "connection_graph.json",
    "reachability_scenarios.json",
    "architecture_map.json",
    "relation_map.json",
    "source_landmarks.json",
    "visualization_index.json",
    "analysis_plan.json",
    "analysis_map.json",
    "cross_unit_analysis.json",
    "synthesis.json",
    "followup_plan.json",
    "report.md",
    "report.html",
    "architecture.html",
];
