//! Unit-analysis and synthesis loop commands.
//!
//! These commands only read Git-SCV artifacts and user-supplied analysis JSON.
//! They do not inspect, execute, or import target repository files.

use crate::cli::{RunDirArgs, ValidateUnitArgs};
use crate::errors::ScvError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

pub fn validate_unit(args: ValidateUnitArgs) -> Result<(), ScvError> {
    ensure_run_dir(&args.run_dir)?;
    if !args.unit_file.is_file() {
        return Err(ScvError::Usage(format!(
            "오류: unit-analysis JSON 파일이 아니다: {}",
            args.unit_file.display()
        )));
    }

    let evidence_ids = read_evidence_ids(&args.run_dir)?;
    let unit = read_json_file(&args.unit_file, "unit-analysis")?;
    let result = validate_unit_value(&unit, &evidence_ids);
    if !result.errors.is_empty() {
        return Err(ScvError::Validation(result.errors));
    }

    println!("unit_validation=ok");
    println!("unit_id={}", result.unit_id);
    println!("claims={}", result.claims_count);
    println!("unresolved_questions={}", result.unresolved_questions_count);
    Ok(())
}

pub(crate) fn validate_unit_value_for_import(run_dir: &Path, unit: &Value) -> Result<(), ScvError> {
    ensure_run_dir(run_dir)?;
    let evidence_ids = read_evidence_ids(run_dir)?;
    let result = validate_unit_value(unit, &evidence_ids);
    if result.errors.is_empty() {
        Ok(())
    } else {
        Err(ScvError::Validation(result.errors))
    }
}

pub fn validate_units(args: RunDirArgs) -> Result<(), ScvError> {
    ensure_run_dir(&args.run_dir)?;
    let dir = args.run_dir.join("unit-analysis");
    if !dir.is_dir() {
        return Err(ScvError::Validation(vec![
            "unit-analysis-missing: unit-analysis 디렉터리가 없다".into(),
        ]));
    }

    let evidence_ids = read_evidence_ids(&args.run_dir)?;
    let mut files = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|err| {
        ScvError::Inspect(format!(
            "validate-units: unit-analysis 디렉터리를 읽지 못했다: {}: {err}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|err| {
            ScvError::Inspect(format!("validate-units: 디렉터리 항목 읽기 실패: {err}"))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();

    if files.is_empty() {
        return Err(ScvError::Validation(vec![
            "unit-analysis-missing: unit-analysis/*.json 파일이 없다".into(),
        ]));
    }

    let mut errors = Vec::new();
    let mut ok_count = 0usize;
    for path in &files {
        match read_json_file(path, "unit-analysis") {
            Ok(unit) => {
                let result = validate_unit_value(&unit, &evidence_ids);
                if result.errors.is_empty() {
                    ok_count += 1;
                } else {
                    for error in result.errors {
                        errors.push(format!("{}: {error}", path.display()));
                    }
                }
            }
            Err(err) => errors.push(err.user_message()),
        }
    }

    if !errors.is_empty() {
        return Err(ScvError::Validation(errors));
    }

    println!("unit_validations={ok_count}");
    println!("unit_validation=ok");
    Ok(())
}

pub fn synthesize(args: RunDirArgs) -> Result<(), ScvError> {
    ensure_run_dir(&args.run_dir)?;
    for name in [
        "artifact_manifest.json",
        "source.json",
        "review.json",
        "connection_graph.json",
        "cross_unit_analysis.json",
        "synthesis.json",
        "followup_plan.json",
    ] {
        require_artifact(&args.run_dir, name)?;
    }

    let synthesis = read_artifact(&args.run_dir, "synthesis.json")?;
    let cross = read_artifact(&args.run_dir, "cross_unit_analysis.json")?;
    let mut errors = Vec::new();
    if synthesis.get("safe_claim_made").and_then(Value::as_bool) != Some(false) {
        errors.push("synthesis-safe-claim: synthesis.json safe_claim_made must be false".into());
    }
    if synthesis.get("aggregate_safety_diagnosis").is_none() {
        errors.push(
            "synthesis-diagnosis-missing: synthesis.json aggregate_safety_diagnosis is missing"
                .into(),
        );
    }
    if cross
        .get("followup_required")
        .and_then(Value::as_bool)
        .is_none()
    {
        errors.push(
            "cross-unit-followup-missing: cross_unit_analysis.json followup_required is missing"
                .into(),
        );
    }
    if !errors.is_empty() {
        return Err(ScvError::Validation(errors));
    }

    println!("synthesis=ok");
    println!("verdict={}", string_field(&synthesis, "verdict"));
    println!(
        "safe_claim_made={}",
        synthesis
            .get("safe_claim_made")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    println!(
        "cross_unit_analysis_complete={}",
        string_field(&synthesis, "cross_unit_analysis_complete")
    );
    println!(
        "required_user_actions={}",
        array_len(&synthesis, "required_user_actions")
    );
    println!(
        "followup_required={}",
        cross
            .get("followup_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    Ok(())
}

pub fn followup_plan(args: RunDirArgs) -> Result<(), ScvError> {
    ensure_run_dir(&args.run_dir)?;
    let plan = read_artifact(&args.run_dir, "followup_plan.json")?;
    validate_followup_value(&plan)?;

    println!("followup_plan=ok");
    println!("round={}", integer_field(&plan, "round"));
    println!("reason={}", string_field(&plan, "reason"));
    println!(
        "required_followups={}",
        array_len(&plan, "required_followups")
    );
    println!(
        "blocked_until={}",
        string_array_join(&plan, "blocked_until")
    );
    Ok(())
}

pub fn validate_followup(args: RunDirArgs) -> Result<(), ScvError> {
    ensure_run_dir(&args.run_dir)?;
    let plan = read_artifact(&args.run_dir, "followup_plan.json")?;
    validate_followup_value(&plan)?;
    println!("followup_validation=ok");
    println!(
        "required_followups={}",
        array_len(&plan, "required_followups")
    );
    Ok(())
}

struct UnitValidation {
    unit_id: String,
    claims_count: usize,
    unresolved_questions_count: usize,
    errors: Vec<String>,
}

fn validate_unit_value(unit: &Value, evidence_ids: &BTreeSet<String>) -> UnitValidation {
    let mut errors = Vec::new();
    let unit_id =
        required_string(unit, "unit_id", &mut errors).unwrap_or_else(|| "<unknown-unit>".into());
    let allowed_paths = required_string_array(unit, "allowed_paths", &mut errors);
    let forbidden_paths = required_string_array(unit, "forbidden_paths", &mut errors);
    let claims = required_array(unit, "claims", &mut errors);
    let connections = required_array(unit, "connections_observed", &mut errors);
    let unresolved_questions = required_array(unit, "unresolved_questions", &mut errors);
    let quality = validate_quality_fields(unit, &claims, &connections, &mut errors);

    for path in allowed_paths.iter().chain(forbidden_paths.iter()) {
        validate_repo_relative_path(path, "unit-analysis-path", &mut errors);
    }

    for (index, claim) in claims.iter().enumerate() {
        validate_claim(
            claim,
            index,
            evidence_ids,
            &allowed_paths,
            &forbidden_paths,
            &mut errors,
        );
    }

    for (index, connection) in connections.iter().enumerate() {
        require_string(
            connection,
            "from",
            &format!("connections_observed[{index}]"),
            &mut errors,
        );
        require_string(
            connection,
            "to",
            &format!("connections_observed[{index}]"),
            &mut errors,
        );
        require_string(
            connection,
            "edge_kind",
            &format!("connections_observed[{index}]"),
            &mut errors,
        );
        validate_evidence_refs(
            connection,
            &format!("connections_observed[{index}]"),
            evidence_ids,
            &mut errors,
        );
    }

    scan_raw_markers(unit, "unit-analysis", &mut errors);
    validate_low_value_analysis(&quality, &mut errors);

    UnitValidation {
        unit_id,
        claims_count: claims.len(),
        unresolved_questions_count: unresolved_questions.len(),
        errors,
    }
}

#[derive(Default)]
struct QualityValidation {
    digest_summary: String,
    digest_points_count: usize,
    map_delta_items_count: usize,
    relation_candidates_count: usize,
    followup_candidates_count: usize,
    abstentions_count: usize,
    claims_count: usize,
    connections_count: usize,
}

fn validate_quality_fields(
    unit: &Value,
    claims: &[&Value],
    connections: &[&Value],
    errors: &mut Vec<String>,
) -> QualityValidation {
    let mut quality = QualityValidation {
        claims_count: claims.len(),
        connections_count: connections.len(),
        ..QualityValidation::default()
    };

    let Some(digest) = unit.get("qualitative_digest").and_then(Value::as_object) else {
        errors.push(
            "qualitative_digest-missing: required object field is missing for worker contract v2.1"
                .into(),
        );
        return quality;
    };
    let digest_value = Value::Object(digest.clone());
    quality.digest_summary =
        required_nested_string(&digest_value, "summary", "qualitative_digest", errors);
    quality.digest_points_count = required_string_array_at(
        &digest_value,
        "important_points",
        "qualitative_digest",
        errors,
    )
    .len();
    let uncertainty = required_string_array_at(
        &digest_value,
        "scoped_uncertainty",
        "qualitative_digest",
        errors,
    );
    for (index, item) in uncertainty.iter().enumerate() {
        if is_generic_uncertainty(item) {
            errors.push(format!(
                "qualitative_digest.scoped_uncertainty[{index}]-generic: uncertainty must be tied to slice boundary, missing evidence, redaction, parser gap, or unresolved relation"
            ));
        }
    }

    let Some(map_delta) = unit.get("map_delta").and_then(Value::as_object) else {
        errors.push(
            "map_delta-missing: required object field is missing for worker contract v2.1".into(),
        );
        return quality;
    };
    let map_delta_value = Value::Object(map_delta.clone());
    for key in [
        "repo_purpose_candidates",
        "major_modules",
        "execution_flows",
        "owner_questions",
        "pre_use_checklist",
    ] {
        quality.map_delta_items_count +=
            required_string_array_at(&map_delta_value, key, "map_delta", errors).len();
    }

    quality.relation_candidates_count = required_array(unit, "relation_candidates", errors).len();
    quality.followup_candidates_count = required_followup_candidates(unit, errors);
    quality.abstentions_count = validate_abstentions(unit, errors);
    quality
}

fn required_nested_string(
    value: &Value,
    key: &str,
    prefix: &str,
    errors: &mut Vec<String>,
) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            errors.push(format!(
                "{prefix}.{key}-missing: required string field is missing"
            ));
            String::new()
        })
}

fn required_followup_candidates(unit: &Value, errors: &mut Vec<String>) -> usize {
    if let Some(items) = unit.get("followup_candidates").and_then(Value::as_array) {
        return items.len();
    }
    if let Some(items) = unit.get("followup_suggestions").and_then(Value::as_array) {
        return items.len();
    }
    errors.push(
        "followup_candidates-missing: required array field is missing for worker contract v2.1"
            .into(),
    );
    0
}

fn validate_abstentions(unit: &Value, errors: &mut Vec<String>) -> usize {
    let abstentions = required_array(unit, "abstentions", errors);
    for (index, abstention) in abstentions.iter().enumerate() {
        let prefix = format!("abstentions[{index}]");
        require_string(abstention, "reason", &prefix, errors);
        require_string(abstention, "scope", &prefix, errors);
    }
    abstentions.len()
}

fn validate_low_value_analysis(quality: &QualityValidation, errors: &mut Vec<String>) {
    let has_slice_specific_digest = !quality.digest_summary.trim().is_empty()
        && !is_generic_uncertainty(&quality.digest_summary);
    let contributes_to_map = quality.digest_points_count > 0
        || quality.map_delta_items_count > 0
        || quality.claims_count > 0
        || quality.connections_count > 0
        || quality.relation_candidates_count > 0
        || quality.followup_candidates_count > 0
        || quality.abstentions_count > 0;
    if !has_slice_specific_digest && !contributes_to_map {
        errors.push(
            "unit-analysis-low-value: generic uncertainty boilerplate without slice-specific digest, map_delta, claim, connection, relation, followup, or scoped abstention"
                .into(),
        );
    }
}

fn is_generic_uncertainty(value: &str) -> bool {
    let text = value.trim().to_ascii_lowercase();
    if text.is_empty() {
        return true;
    }
    let generic = [
        "this slice alone cannot determine",
        "more context is needed",
        "no conclusions can be drawn",
        "cannot determine from this slice alone",
        "insufficient information",
    ];
    generic
        .iter()
        .any(|needle| text == *needle || text.contains(needle))
}

fn validate_claim(
    claim: &Value,
    index: usize,
    evidence_ids: &BTreeSet<String>,
    allowed_paths: &[String],
    forbidden_paths: &[String],
    errors: &mut Vec<String>,
) {
    let prefix = format!("claims[{index}]");
    require_string(claim, "claim_id", &prefix, errors);
    require_string(claim, "type", &prefix, errors);
    require_string(claim, "summary", &prefix, errors);
    require_string(claim, "confidence", &prefix, errors);
    required_array_at(claim, "validated_by_git_scv", &prefix, errors);
    required_array_at(claim, "not_validated_by_git_scv", &prefix, errors);
    validate_evidence_refs(claim, &prefix, evidence_ids, errors);

    let source_paths = required_string_array_at(claim, "source_paths", &prefix, errors);
    if source_paths.is_empty() {
        errors.push(format!(
            "{prefix}.source_paths-empty: claim must be path-bound"
        ));
    }
    for path in &source_paths {
        validate_repo_relative_path(path, &format!("{prefix}.source_paths"), errors);
        if !path_matches_any(path, allowed_paths) {
            errors.push(format!(
                "{prefix}.source_paths-outside-allowed: {path} is outside allowed_paths"
            ));
        }
        if path_matches_any(path, forbidden_paths) {
            errors.push(format!(
                "{prefix}.source_paths-forbidden: {path} is inside forbidden_paths"
            ));
        }
    }
}

fn validate_evidence_refs(
    value: &Value,
    prefix: &str,
    evidence_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let refs = required_string_array_at(value, "evidence_refs", prefix, errors);
    if refs.is_empty() {
        errors.push(format!(
            "{prefix}.evidence_refs-empty: claim must cite evidence"
        ));
    }
    for id in refs {
        if !evidence_ids.contains(&id) {
            errors.push(format!(
                "{prefix}.evidence_refs-missing: evidence id {id} does not exist"
            ));
        }
    }
}

fn validate_followup_value(plan: &Value) -> Result<(), ScvError> {
    let mut errors = Vec::new();
    required_i64(plan, "round", &mut errors);
    required_string(plan, "reason", &mut errors);
    let required_followups = required_array(plan, "required_followups", &mut errors);
    required_string_array(plan, "blocked_until", &mut errors);

    for (index, item) in required_followups.iter().enumerate() {
        let prefix = format!("required_followups[{index}]");
        require_string(item, "followup_id", &prefix, &mut errors);
        require_string(item, "kind", &prefix, &mut errors);
        require_string(item, "question", &prefix, &mut errors);
        required_array_at(item, "needed_artifacts", &prefix, &mut errors);
    }

    scan_raw_markers(plan, "followup_plan", &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ScvError::Validation(errors))
    }
}

fn ensure_run_dir(path: &Path) -> Result<(), ScvError> {
    if !path.is_dir() {
        return Err(ScvError::Usage(format!(
            "오류: Git-SCV run/case 디렉터리가 아니다: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_artifact(run_dir: &Path, name: &str) -> Result<(), ScvError> {
    let path = run_dir.join(name);
    if !path.is_file() {
        return Err(ScvError::Validation(vec![format!(
            "artifact-missing: {name} is required"
        )]));
    }
    Ok(())
}

fn read_artifact(run_dir: &Path, name: &str) -> Result<Value, ScvError> {
    require_artifact(run_dir, name)?;
    read_json_file(&run_dir.join(name), name)
}

fn read_evidence_ids(run_dir: &Path) -> Result<BTreeSet<String>, ScvError> {
    let evidence = read_artifact(run_dir, "evidence.json")?;
    let mut ids = BTreeSet::new();
    let Some(items) = evidence.get("evidence").and_then(Value::as_array) else {
        return Err(ScvError::Validation(vec![
            "evidence-shape: evidence.json must contain evidence array".into(),
        ]));
    };
    for item in items {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            ids.insert(id.to_string());
        }
    }
    Ok(ids)
}

fn read_json_file(path: &Path, label: &str) -> Result<Value, ScvError> {
    let bytes = fs::read(path).map_err(|err| {
        ScvError::Inspect(format!(
            "{label}: JSON 파일을 읽지 못했다: {}: {err}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ScvError::Inspect(format!(
            "{label}: JSON을 해석하지 못했다: {}: {err}",
            path.display()
        ))
    })
}

fn required_string(value: &Value, key: &str, errors: &mut Vec<String>) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            errors.push(format!("{key}-missing: required string field is missing"));
            None
        })
}

fn require_string(value: &Value, key: &str, prefix: &str, errors: &mut Vec<String>) {
    if value.get(key).and_then(Value::as_str).is_none() {
        errors.push(format!(
            "{prefix}.{key}-missing: required string field is missing"
        ));
    }
}

fn required_i64(value: &Value, key: &str, errors: &mut Vec<String>) -> Option<i64> {
    value.get(key).and_then(Value::as_i64).or_else(|| {
        errors.push(format!("{key}-missing: required integer field is missing"));
        None
    })
}

fn required_array<'a>(value: &'a Value, key: &str, errors: &mut Vec<String>) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_else(|| {
            errors.push(format!("{key}-missing: required array field is missing"));
            Vec::new()
        })
}

fn required_array_at<'a>(
    value: &'a Value,
    key: &str,
    prefix: &str,
    errors: &mut Vec<String>,
) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_else(|| {
            errors.push(format!(
                "{prefix}.{key}-missing: required array field is missing"
            ));
            Vec::new()
        })
}

fn required_string_array(value: &Value, key: &str, errors: &mut Vec<String>) -> Vec<String> {
    required_string_array_inner(value, key, key, errors)
}

fn required_string_array_at(
    value: &Value,
    key: &str,
    prefix: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    required_string_array_inner(value, key, &format!("{prefix}.{key}"), errors)
}

fn required_string_array_inner(
    value: &Value,
    key: &str,
    label: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let Some(items) = value.get(key).and_then(Value::as_array) else {
        errors.push(format!(
            "{label}-missing: required string array field is missing"
        ));
        return Vec::new();
    };
    let mut strings = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(text) = item.as_str() {
            strings.push(text.to_string());
        } else {
            errors.push(format!("{label}[{index}]-invalid: value must be a string"));
        }
    }
    strings
}

fn validate_repo_relative_path(path: &str, label: &str, errors: &mut Vec<String>) {
    if path.is_empty() {
        errors.push(format!("{label}-empty: path is empty"));
        return;
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        errors.push(format!("{label}-absolute: {path} must be repo-relative"));
    }
    for component in parsed.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            errors.push(format!(
                "{label}-invalid: {path} must not contain absolute or parent components"
            ));
            break;
        }
    }
}

fn path_matches_any(path: &str, candidates: &[String]) -> bool {
    candidates.iter().any(|candidate| {
        path == candidate
            || candidate
                .strip_suffix('/')
                .is_some_and(|dir| path.starts_with(&format!("{dir}/")))
    })
}

fn scan_raw_markers(value: &Value, path: &str, errors: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            for marker in [
                "GIT_SCV_FAKE_TOKEN_DO_NOT_USE",
                "GIT_SCV_FAKE_BEARER_DO_NOT_USE",
                "ghp_FAKE",
                "Authorization:",
                "Bearer ",
                "?token=",
                "&token=",
                "<script",
                "onerror=",
                "javascript:",
            ] {
                if text.contains(marker) {
                    errors.push(format!(
                        "{path}-raw-marker: raw marker `{marker}` must not appear in analysis artifacts"
                    ));
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_raw_markers(item, &format!("{path}[{index}]"), errors);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                scan_raw_markers(item, &format!("{path}.{key}"), errors);
            }
        }
        _ => {}
    }
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn integer_field(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn string_array_join(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn worker_contract_v21_accepts_quality_fields_without_claims() {
        let unit = valid_quality_unit();
        let result = validate_unit_value(&unit, &BTreeSet::new());
        assert!(result.errors.is_empty(), "{:?}", result.errors);
    }

    #[test]
    fn worker_contract_v21_requires_qualitative_digest() {
        let mut unit = valid_quality_unit();
        unit.as_object_mut().unwrap().remove("qualitative_digest");
        let result = validate_unit_value(&unit, &BTreeSet::new());
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("qualitative_digest-missing")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn worker_contract_v21_rejects_generic_boilerplate_only() {
        let unit = json!({
            "unit_id": "U0001",
            "allowed_paths": ["src/lib.rs"],
            "forbidden_paths": [],
            "claims": [],
            "connections_observed": [],
            "unresolved_questions": [],
            "qualitative_digest": {
                "summary": "This slice alone cannot determine the repository behavior.",
                "important_points": [],
                "scoped_uncertainty": []
            },
            "map_delta": {
                "repo_purpose_candidates": [],
                "major_modules": [],
                "execution_flows": [],
                "owner_questions": [],
                "pre_use_checklist": []
            },
            "relation_candidates": [],
            "followup_candidates": [],
            "abstentions": []
        });
        let result = validate_unit_value(&unit, &BTreeSet::new());
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("unit-analysis-low-value")),
            "{:?}",
            result.errors
        );
    }

    #[test]
    fn worker_contract_v21_accepts_legacy_followup_suggestions_alias() {
        let mut unit = valid_quality_unit();
        let object = unit.as_object_mut().unwrap();
        object.remove("followup_candidates");
        object.insert(
            "followup_suggestions".into(),
            json!(["Review adjacent package manifest."]),
        );
        let result = validate_unit_value(&unit, &BTreeSet::new());
        assert!(result.errors.is_empty(), "{:?}", result.errors);
    }

    #[test]
    fn worker_contract_v21_accepts_scoped_abstention() {
        let unit = json!({
            "unit_id": "U0001",
            "allowed_paths": ["src/lib.rs"],
            "forbidden_paths": [],
            "claims": [],
            "connections_observed": [],
            "unresolved_questions": [],
            "qualitative_digest": {
                "summary": "",
                "important_points": [],
                "scoped_uncertainty": []
            },
            "map_delta": {
                "repo_purpose_candidates": [],
                "major_modules": [],
                "execution_flows": [],
                "owner_questions": [],
                "pre_use_checklist": []
            },
            "relation_candidates": [],
            "followup_candidates": [],
            "abstentions": [
                {"reason": "Export contained only redacted binary metadata.", "scope": "src/lib.rs"}
            ]
        });
        let result = validate_unit_value(&unit, &BTreeSet::new());
        assert!(result.errors.is_empty(), "{:?}", result.errors);
    }

    fn valid_quality_unit() -> Value {
        json!({
            "unit_id": "U0001",
            "allowed_paths": ["src/lib.rs"],
            "forbidden_paths": [],
            "claims": [],
            "connections_observed": [],
            "unresolved_questions": [],
            "qualitative_digest": {
                "summary": "This slice defines a small Rust library module.",
                "important_points": ["src/lib.rs is the visible library surface in this slice."],
                "scoped_uncertainty": ["Only src/lib.rs was included in this unit export."]
            },
            "map_delta": {
                "repo_purpose_candidates": ["Rust library module"],
                "major_modules": ["src/lib.rs"],
                "execution_flows": [],
                "owner_questions": ["Which binary or package manifest wires this module into runtime use?"],
                "pre_use_checklist": ["Review manifest scripts before installing."]
            },
            "relation_candidates": [],
            "followup_candidates": [],
            "abstentions": []
        })
    }
}
