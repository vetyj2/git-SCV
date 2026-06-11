//! 모델 입력용 읽기 슬라이스 계획.
//!
//! 파일 본문은 읽지 않는다. `sectors.json`의 권장 읽기 순서와
//! `gates.json`의 승인 후보 목록을 조합해, 후속 에이전트가 작은 단위로
//! 읽을 수 있는 경로 묶음만 만든다.

use crate::model::{
    Entry, EntryKind, GateArtifact, InventoryArtifact, SectorsArtifact, Slice, SliceArtifact,
    SliceFile, SlicePolicy, SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ESTIMATED_TOKENS_PER_SLICE: u64 = 8_000;

pub fn build(
    inventory: &InventoryArtifact,
    sectors: &SectorsArtifact,
    gates: &GateArtifact,
    run_id: &str,
) -> SliceArtifact {
    let entries = inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let sensitive = gate_paths(&gates.sensitive_candidates);
    let automatic_execution = gate_paths(&gates.automatic_execution_candidates);
    let execution_related = gate_paths(&gates.execution_related_candidates);

    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    for path in &sectors.suggested_read_order {
        if let Some(entry) = entries.get(path.as_str()) {
            push_slice_file(
                &mut ordered,
                &mut seen,
                entry,
                &sensitive,
                &automatic_execution,
                &execution_related,
            );
        }
    }
    for entry in entries.values() {
        push_slice_file(
            &mut ordered,
            &mut seen,
            entry,
            &sensitive,
            &automatic_execution,
            &execution_related,
        );
    }

    SliceArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        policy: SlicePolicy {
            source_order: "sectors.suggested_read_order".into(),
            max_estimated_tokens_per_slice: MAX_ESTIMATED_TOKENS_PER_SLICE,
            default_model_input:
                "sensitive candidates are listed but excluded unless separately approved".into(),
        },
        slices: pack_slices(ordered),
        note: "슬라이스는 후속 모델 입력 계획이며 파일 본문을 포함하지 않는다. 단일 파일이 한도를 넘으면 별도 슬라이스로 두고 over_token_limit=true로 표시한다.".into(),
    }
}

fn push_slice_file(
    out: &mut Vec<SliceFile>,
    seen: &mut BTreeSet<String>,
    entry: &Entry,
    sensitive: &BTreeSet<String>,
    automatic_execution: &BTreeSet<String>,
    execution_related: &BTreeSet<String>,
) {
    if !seen.insert(entry.path.clone()) {
        return;
    }
    let bytes = entry.size.unwrap_or(0);
    let sensitive_candidate = sensitive.contains(&entry.path);
    out.push(SliceFile {
        path: entry.path.clone(),
        bytes,
        estimated_tokens: bytes.div_ceil(4),
        sector: sector_name(&entry.path),
        default_model_input: !sensitive_candidate,
        sensitive_candidate,
        automatic_execution_candidate: automatic_execution.contains(&entry.path),
        execution_related_candidate: execution_related.contains(&entry.path),
    });
}

fn pack_slices(files: Vec<SliceFile>) -> Vec<Slice> {
    let mut slices = Vec::new();
    let mut current = Vec::new();
    let mut current_tokens = 0;

    for file in files {
        let file_tokens = file.estimated_tokens;
        if !current.is_empty() && current_tokens + file_tokens > MAX_ESTIMATED_TOKENS_PER_SLICE {
            push_slice(&mut slices, current, current_tokens);
            current = Vec::new();
            current_tokens = 0;
        }
        current_tokens += file_tokens;
        current.push(file);
    }

    if !current.is_empty() {
        push_slice(&mut slices, current, current_tokens);
    }

    slices
}

fn push_slice(slices: &mut Vec<Slice>, files: Vec<SliceFile>, estimated_tokens: u64) {
    let requires_sensitive_raw_approval = files.iter().any(|file| file.sensitive_candidate);
    let requires_execution_approval = files
        .iter()
        .any(|file| file.automatic_execution_candidate || file.execution_related_candidate);
    slices.push(Slice {
        id: format!("S{:04}", slices.len() + 1),
        files,
        estimated_tokens,
        over_token_limit: estimated_tokens > MAX_ESTIMATED_TOKENS_PER_SLICE,
        requires_sensitive_raw_approval,
        requires_execution_approval,
    });
}

fn gate_paths(items: &[crate::model::GateItem]) -> BTreeSet<String> {
    items.iter().map(|item| item.path.clone()).collect()
}

fn sector_name(path: &str) -> String {
    path.split('/')
        .next()
        .filter(|part| path.contains('/') && !part.is_empty())
        .unwrap_or("(root)")
        .into()
}
