//! 형태 감지.
//!
//! 규칙은 D01–D13 표가 전부다. 내용을 여는 파일은 D01(package.json)뿐이고,
//! D13(비밀값 후보)에 걸린 파일은 어떤 경우에도 열지 않는다(D13이 항상
//! 이긴다). 바이너리 판정: 첫 8KiB 에 NUL 바이트.

use crate::errors::ScvError;
use crate::model::{
    DependencyItem, DependencyManifest, DetectOutcome, Detection, Entry, EntryKind,
    InventoryArtifact, ReadFile, RuleId,
};
use std::path::Path;

/// inventory 의 entries 를 규칙표와 대조하고, D01 파일만 내용을 읽는다.
/// 읽기 집계(read_files, binary_skips)는 coverage.json 의 재료가 된다.
pub fn detect(inventory: &InventoryArtifact, root: &Path) -> Result<DetectOutcome, ScvError> {
    let mut detections = Vec::new();
    let mut read_files = Vec::new();
    let mut binary_skips = 0;
    let mut dependency_manifests = Vec::new();
    let mut limitations = Vec::new();

    for entry in &inventory.entries {
        apply_name_rules(entry, &mut detections);

        if is_file(entry) && name(entry) == "package.json" && !is_secret_candidate(entry) {
            read_package_json(
                root,
                entry,
                &mut detections,
                &mut read_files,
                &mut binary_skips,
                &mut dependency_manifests,
                &mut limitations,
            )?;
        }
    }

    detections.sort_by(|left, right| {
        rule_order(left.rule)
            .cmp(&rule_order(right.rule))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.key.cmp(&right.key))
    });

    Ok(DetectOutcome {
        detections,
        read_files,
        binary_skips,
        dependency_manifests,
        limitations,
    })
}

fn apply_name_rules(entry: &Entry, detections: &mut Vec<Detection>) {
    if is_file(entry) {
        match name(entry) {
            "package.json" => add(detections, RuleId::D01, entry),
            "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" => {
                add(detections, RuleId::D03, entry);
            }
            "Cargo.toml" | "Cargo.lock" => add(detections, RuleId::D04, entry),
            "build.rs" => add(detections, RuleId::D05, entry),
            "Makefile" | "makefile" | "GNUmakefile" => add(detections, RuleId::D06, entry),
            ".envrc" => add(detections, RuleId::D10, entry),
            _ => {}
        }

        if is_container_file(entry) {
            add(detections, RuleId::D07, entry);
        }
        if entry.path.starts_with(".github/workflows/")
            && matches!(entry.ext.as_deref(), Some("yml" | "yaml"))
        {
            add(detections, RuleId::D08, entry);
        }
        if matches!(entry.ext.as_deref(), Some("sh" | "bash" | "zsh")) {
            add(detections, RuleId::D09, entry);
        }
        if entry.path.ends_with(".vscode/tasks.json") {
            add(detections, RuleId::D11, entry);
        }
        if is_secret_candidate(entry) {
            add(detections, RuleId::D13, entry);
        }
    }

    if entry.kind == EntryKind::Dir && name(entry) == ".husky" {
        add(detections, RuleId::D12, entry);
    }
}

fn read_package_json(
    root: &Path,
    entry: &Entry,
    detections: &mut Vec<Detection>,
    read_files: &mut Vec<ReadFile>,
    binary_skips: &mut u64,
    dependency_manifests: &mut Vec<DependencyManifest>,
    limitations: &mut Vec<String>,
) -> Result<(), ScvError> {
    let path = root.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|err| {
        ScvError::Inspect(format!(
            "detect: package.json을 읽지 못했다: {}: {err}",
            entry.path
        ))
    })?;

    read_files.push(ReadFile {
        path: entry.path.clone(),
        bytes: bytes.len() as u64,
    });

    if bytes.iter().take(8192).any(|byte| *byte == 0) {
        *binary_skips += 1;
        return Ok(());
    }

    let parsed = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            limitations.push(format!("package.json을 파싱하지 못했다: {}", entry.path));
            return Ok(());
        }
    };

    dependency_manifests.push(dependency_manifest(&entry.path, &parsed));

    let Some(scripts) = parsed.get("scripts").and_then(|value| value.as_object()) else {
        return Ok(());
    };

    let source = String::from_utf8_lossy(&bytes);
    for key in ["preinstall", "install", "postinstall", "prepare"] {
        if scripts.contains_key(key) {
            let (line, excerpt) = find_key_line(&source, key);
            detections.push(Detection {
                rule: RuleId::D02,
                path: entry.path.clone(),
                line,
                key: Some(key.into()),
                excerpt,
            });
        }
    }

    Ok(())
}

fn dependency_manifest(path: &str, parsed: &serde_json::Value) -> DependencyManifest {
    let mut dependencies = Vec::new();
    for scope in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ] {
        if let Some(map) = parsed.get(scope).and_then(|value| value.as_object()) {
            for (name, spec) in map {
                dependencies.push(DependencyItem {
                    name: name.clone(),
                    scope: scope.into(),
                    source_kind: dependency_source_kind(spec),
                });
            }
        }
    }
    dependencies.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.name.cmp(&right.name))
    });
    DependencyManifest {
        path: path.into(),
        ecosystem: "npm".into(),
        dependencies,
    }
}

fn dependency_source_kind(spec: &serde_json::Value) -> String {
    let Some(value) = spec.as_str() else {
        return "non-string".into();
    };
    let lower = value.to_lowercase();
    if lower.starts_with("workspace:") {
        "workspace".into()
    } else if lower.starts_with("file:") || lower.starts_with("link:") {
        "local-path".into()
    } else if lower.starts_with("git:")
        || lower.starts_with("git+")
        || lower.contains("github:")
        || lower.contains("gitlab:")
    {
        "git".into()
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        "url".into()
    } else if lower.starts_with("npm:") {
        "alias".into()
    } else {
        "registry".into()
    }
}

fn add(detections: &mut Vec<Detection>, rule: RuleId, entry: &Entry) {
    detections.push(Detection {
        rule,
        path: entry.path.clone(),
        line: None,
        key: None,
        excerpt: None,
    });
}

fn is_file(entry: &Entry) -> bool {
    entry.kind == EntryKind::File
}

fn name(entry: &Entry) -> &str {
    entry.path.rsplit('/').next().unwrap_or(entry.path.as_str())
}

fn is_container_file(entry: &Entry) -> bool {
    let file_name = name(entry);
    file_name.starts_with("Dockerfile")
        || matches!(
            file_name,
            "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
        )
}

fn is_secret_candidate(entry: &Entry) -> bool {
    let file_name = name(entry);
    let lower_name = file_name.to_lowercase();
    file_name == ".env"
        || file_name.starts_with(".env.")
        || ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
            .iter()
            .any(|prefix| file_name.starts_with(prefix))
        || matches!(entry.ext.as_deref(), Some("pem" | "p12" | "pfx"))
        || lower_name.contains("credential")
        || lower_name.contains("secret")
}

fn find_key_line(source: &str, key: &str) -> (Option<u32>, Option<String>) {
    let needle = format!("\"{key}\"");
    for (index, line) in source.lines().enumerate() {
        if line.contains(&needle) {
            return (
                Some(index as u32 + 1),
                Some(truncate_chars(line.trim(), 200)),
            );
        }
    }
    (None, None)
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn rule_order(rule: RuleId) -> u8 {
    match rule {
        RuleId::D01 => 1,
        RuleId::D02 => 2,
        RuleId::D03 => 3,
        RuleId::D04 => 4,
        RuleId::D05 => 5,
        RuleId::D06 => 6,
        RuleId::D07 => 7,
        RuleId::D08 => 8,
        RuleId::D09 => 9,
        RuleId::D10 => 10,
        RuleId::D11 => 11,
        RuleId::D12 => 12,
        RuleId::D13 => 13,
    }
}
