//! 섹터 지도.
//!
//! 에이전트의 읽기 계획 보조 자료다. 섹터 = 최상위 디렉터리, 루트 직속
//! 파일은 "(root)". 추정 토큰 = ceil(bytes / 4). 권장 읽기 순서는
//! 매니페스트 → 자동 실행 지점 → 진입점 후보 → 크기 오름차순, 최대 200개.

use crate::model::{
    Detection, EntryKind, InventoryArtifact, RuleId, Sector, SectorsArtifact, SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn build(
    inventory: &InventoryArtifact,
    detections: &[Detection],
    run_id: &str,
) -> SectorsArtifact {
    let mut sectors = BTreeMap::<String, SectorAcc>::new();
    for entry in inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
    {
        let name = sector_name(&entry.path);
        let acc = sectors.entry(name).or_default();
        acc.files += 1;
        acc.bytes += entry.size.unwrap_or(0);
        let ext = entry.ext.clone().unwrap_or_else(|| "(none)".into());
        *acc.extensions.entry(ext).or_insert(0) += 1;
    }

    for detection in detections {
        let name = sector_name(&detection.path);
        sectors.entry(name).or_default().detections += 1;
    }

    let mut sector_items = sectors
        .into_iter()
        .map(|(name, acc)| Sector {
            name,
            files: acc.files,
            bytes: acc.bytes,
            estimated_tokens: acc.bytes.div_ceil(4),
            extensions: acc.extensions,
            detections: acc.detections,
        })
        .collect::<Vec<_>>();
    sector_items
        .sort_by(|left, right| sector_sort_key(&left.name).cmp(&sector_sort_key(&right.name)));

    let mut note = "읽기 계획 보조 자료이며 판단 근거가 아니다.".to_string();
    let mut suggested_read_order = suggested_read_order(inventory, detections);
    if suggested_read_order.len() > 200 {
        suggested_read_order.truncate(200);
        note.push_str(" 읽기 순서는 200개로 잘렸다.");
    }

    SectorsArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        sectors: sector_items,
        suggested_read_order,
        note,
    }
}

#[derive(Default)]
struct SectorAcc {
    files: u64,
    bytes: u64,
    extensions: BTreeMap<String, u64>,
    detections: u64,
}

fn sector_name(path: &str) -> String {
    path.split('/')
        .next()
        .filter(|part| path.contains('/') && !part.is_empty())
        .unwrap_or("(root)")
        .into()
}

fn sector_sort_key(name: &str) -> (u8, &str) {
    if name == "(root)" {
        (0, name)
    } else {
        (1, name)
    }
}

fn suggested_read_order(inventory: &InventoryArtifact, detections: &[Detection]) -> Vec<String> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();

    push_detection_paths(
        &mut order,
        &mut seen,
        detections,
        &[RuleId::D01, RuleId::D03, RuleId::D04],
    );
    push_detection_paths(
        &mut order,
        &mut seen,
        detections,
        &[
            RuleId::D02,
            RuleId::D05,
            RuleId::D10,
            RuleId::D11,
            RuleId::D12,
        ],
    );

    for candidate in [
        "src/main.rs",
        "src/lib.rs",
        "main.py",
        "app.py",
        "index.js",
        "index.ts",
        "main.go",
    ] {
        if has_file(inventory, candidate) {
            push_unique(&mut order, &mut seen, candidate);
        }
    }

    let mut remaining = inventory
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::File)
        .collect::<Vec<_>>();
    remaining.sort_by(|left, right| {
        left.size
            .unwrap_or(0)
            .cmp(&right.size.unwrap_or(0))
            .then_with(|| left.path.cmp(&right.path))
    });
    for entry in remaining {
        push_unique(&mut order, &mut seen, &entry.path);
    }

    order
}

fn push_detection_paths(
    order: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    detections: &[Detection],
    rules: &[RuleId],
) {
    let mut paths = detections
        .iter()
        .filter(|detection| rules.contains(&detection.rule))
        .map(|detection| detection.path.as_str())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    for path in paths {
        push_unique(order, seen, path);
    }
}

fn has_file(inventory: &InventoryArtifact, path: &str) -> bool {
    inventory
        .entries
        .iter()
        .any(|entry| entry.kind == EntryKind::File && entry.path == path)
}

fn push_unique(order: &mut Vec<String>, seen: &mut BTreeSet<String>, path: &str) {
    if seen.insert(path.into()) {
        order.push(path.into());
    }
}
