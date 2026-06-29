//! T03 — 감지 규칙 D01–D13. 사양: docs/spec/0500-detect.md 1·2절.

mod common;

use git_scv::detect::detect;
use git_scv::model::{
    Entry, EntryKind, InventoryArtifact, Limits, Policy, RuleId, Totals, SCHEMA_VERSION,
};
use std::fs;

fn entry(path: &str, kind: EntryKind, ext: Option<&str>) -> Entry {
    Entry {
        path: path.into(),
        kind,
        size: if kind == EntryKind::File {
            Some(1)
        } else {
            None
        },
        ext: ext.map(|s| s.into()),
        symlink_target: None,
    }
}

fn inventory(entries: Vec<Entry>, root: &str) -> InventoryArtifact {
    let listed = entries.len() as u64;
    InventoryArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: "scv-test".into(),
        root: root.into(),
        policy: Policy::default(),
        limits: Limits::default(),
        entries,
        skipped: vec![],
        totals: Totals {
            discovered: listed,
            listed,
            skipped: 0,
        },
    }
}

fn rule_paths(outcome: &git_scv::model::DetectOutcome, rule: RuleId) -> Vec<String> {
    outcome
        .detections
        .iter()
        .filter(|d| d.rule == rule)
        .map(|d| d.path.clone())
        .collect()
}

#[test]
fn t03_d01_d02_package_json_hooks() {
    let root = common::temp_dir("t03-d01");
    fs::write(
        root.join("package.json"),
        "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"postinstall\": \"node s.js\",\n    \"prepare\": \"node p.js\",\n    \"test\": \"echo ok\"\n  }\n}\n",
    )
    .unwrap();
    let inv = inventory(
        vec![entry("package.json", EntryKind::File, Some("json"))],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    assert_eq!(rule_paths(&outcome, RuleId::D01), vec!["package.json"]);

    let d02: Vec<_> = outcome
        .detections
        .iter()
        .filter(|d| d.rule == RuleId::D02)
        .collect();
    let keys: Vec<_> = d02.iter().map(|d| d.key.clone().unwrap()).collect();
    assert!(keys.contains(&"postinstall".to_string()), "{keys:?}");
    assert!(keys.contains(&"prepare".to_string()), "{keys:?}");
    assert!(
        !keys.contains(&"test".to_string()),
        "test 키는 자동 실행 훅이 아니다"
    );
    for d in &d02 {
        assert!(d.line.is_some(), "D02는 줄 번호 필수 (9002)");
        assert!(d.excerpt.is_some(), "D02는 줄 원문 발췌 필수");
    }
    // 읽기 집계 (0905)
    assert_eq!(outcome.read_files.len(), 1);
    assert_eq!(outcome.read_files[0].path, "package.json");
}

#[test]
fn t03_package_json_dependency_summary_redacts_specs() {
    let root = common::temp_dir("t03-dependencies");
    fs::write(
        root.join("package.json"),
        "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.3.0\",\n    \"private-url\": \"https://token@example.invalid/pkg.tgz\",\n    \"local-lib\": \"file:../local-lib\",\n    \"git-lib\": \"git+https://example.invalid/repo.git\"\n  },\n  \"devDependencies\": {\n    \"alias-lib\": \"npm:left-pad@1.3.0\"\n  }\n}\n",
    )
    .unwrap();
    let inv = inventory(
        vec![entry("package.json", EntryKind::File, Some("json"))],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    assert_eq!(outcome.dependency_manifests.len(), 1);
    let deps = &outcome.dependency_manifests[0].dependencies;
    assert!(deps
        .iter()
        .any(|item| item.name == "left-pad" && item.source_kind == "registry"));
    assert!(deps
        .iter()
        .any(|item| item.name == "private-url" && item.source_kind == "url"));
    assert!(deps
        .iter()
        .any(|item| item.name == "local-lib" && item.source_kind == "local-path"));
    assert!(deps
        .iter()
        .any(|item| item.name == "git-lib" && item.source_kind == "git"));
    assert!(deps
        .iter()
        .any(|item| item.name == "alias-lib" && item.source_kind == "alias"));
    let git = deps.iter().find(|item| item.name == "git-lib").unwrap();
    assert!(!git.raw_spec_stored);
    assert!(git.redacted_spec.starts_with("git+https://"));
    assert!(git.spec_hash.starts_with("sha256:"));
    assert!(git.risk_signals.contains(&"git-dependency".into()));
    assert!(git.risk_signals.contains(&"unpinned-ref".into()));
    let private_url = deps.iter().find(|item| item.name == "private-url").unwrap();
    assert!(!private_url.raw_spec_stored);
    assert!(private_url.spec_hash.starts_with("sha256:"));
    assert!(private_url.risk_signals.contains(&"url-dependency".into()));
    assert!(private_url
        .risk_signals
        .contains(&"private-registry-like".into()));

    let serialized = serde_json::to_string(&outcome.dependency_manifests).unwrap();
    assert!(!serialized.contains("token@example.invalid"));
    assert!(!serialized.contains("^1.3.0"));
}

#[test]
fn t03_d03_to_d12_name_rules() {
    let root = common::temp_dir("t03-rest");
    let inv = inventory(
        vec![
            entry("yarn.lock", EntryKind::File, Some("lock")),
            entry("Cargo.toml", EntryKind::File, Some("toml")),
            entry("native/build.rs", EntryKind::File, Some("rs")),
            entry("Makefile", EntryKind::File, None),
            entry("Justfile", EntryKind::File, None),
            entry("pyproject.toml", EntryKind::File, Some("toml")),
            entry("setup.py", EntryKind::File, Some("py")),
            entry("go.mod", EntryKind::File, Some("mod")),
            entry("Gemfile", EntryKind::File, None),
            entry(".pre-commit-config.yaml", EntryKind::File, Some("yaml")),
            entry("Dockerfile", EntryKind::File, None),
            entry(".github/workflows/ci.yml", EntryKind::File, Some("yml")),
            entry("setup.sh", EntryKind::File, Some("sh")),
            entry(".envrc", EntryKind::File, None),
            entry(".vscode/tasks.json", EntryKind::File, Some("json")),
            entry(".husky", EntryKind::Dir, None),
        ],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    assert_eq!(rule_paths(&outcome, RuleId::D03), vec!["yarn.lock"]);
    assert_eq!(rule_paths(&outcome, RuleId::D04), vec!["Cargo.toml"]);
    assert_eq!(rule_paths(&outcome, RuleId::D05), vec!["native/build.rs"]);
    assert_eq!(
        rule_paths(&outcome, RuleId::D06),
        vec!["Justfile", "Makefile"]
    );
    assert_eq!(rule_paths(&outcome, RuleId::D07), vec!["Dockerfile"]);
    assert_eq!(
        rule_paths(&outcome, RuleId::D08),
        vec![".github/workflows/ci.yml"]
    );
    assert_eq!(rule_paths(&outcome, RuleId::D09), vec!["setup.sh"]);
    assert_eq!(rule_paths(&outcome, RuleId::D10), vec![".envrc"]);
    assert_eq!(
        rule_paths(&outcome, RuleId::D11),
        vec![".vscode/tasks.json"]
    );
    assert_eq!(rule_paths(&outcome, RuleId::D12), vec![".husky"]);
    assert_eq!(
        rule_paths(&outcome, RuleId::D14),
        vec![
            ".pre-commit-config.yaml",
            "Gemfile",
            "go.mod",
            "pyproject.toml",
            "setup.py"
        ]
    );
    // 이 입력에는 D13이 없어야 한다
    assert!(rule_paths(&outcome, RuleId::D13).is_empty());
}

#[test]
fn t03_d13_secret_names_never_read() {
    let root = common::temp_dir("t03-d13");
    fs::write(root.join(".env"), "TOP_SECRET=do-not-open").unwrap();
    let inv = inventory(
        vec![
            entry(".env", EntryKind::File, None),
            entry(".env.local", EntryKind::File, Some("local")),
            entry("keys/id_rsa", EntryKind::File, None),
            entry("cert.pem", EntryKind::File, Some("pem")),
            entry("My-Credentials.txt", EntryKind::File, Some("txt")),
            entry(".npmrc", EntryKind::File, None),
            entry(".pypirc", EntryKind::File, None),
            entry(".aws/credentials", EntryKind::File, None),
            entry(".kube/config", EntryKind::File, None),
            entry("deploy.key", EntryKind::File, Some("key")),
            entry("service-account-prod.json", EntryKind::File, Some("json")),
        ],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    let d13 = rule_paths(&outcome, RuleId::D13);
    for p in [
        ".env",
        ".env.local",
        "keys/id_rsa",
        "cert.pem",
        "My-Credentials.txt",
        ".npmrc",
        ".pypirc",
        ".aws/credentials",
        ".kube/config",
        "deploy.key",
        "service-account-prod.json",
    ] {
        assert!(d13.contains(&p.to_string()), "D13 누락: {p} / {d13:?}");
    }
    // 1103, 1104 — 비밀 후보는 어떤 경우에도 읽지 않는다
    assert!(
        outcome.read_files.is_empty(),
        "비밀 후보 파일을 읽었다: {:?}",
        outcome.read_files
    );
}

#[test]
fn t03_secret_named_script_keeps_both_findings_without_reading() {
    let root = common::temp_dir("t03-secret-script");
    fs::write(root.join(".env.sh"), "SHOULD_NOT_BE_READ=1\nrm -rf nope\n").unwrap();
    let inv = inventory(
        vec![entry(".env.sh", EntryKind::File, Some("sh"))],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    assert_eq!(rule_paths(&outcome, RuleId::D09), vec![".env.sh"]);
    assert_eq!(rule_paths(&outcome, RuleId::D13), vec![".env.sh"]);
    assert!(
        outcome.read_files.is_empty(),
        "비밀 후보 스크립트 내용을 읽었다: {:?}",
        outcome.read_files
    );
}

#[test]
fn t03_binary_package_json_skipped() {
    // 첫 8KiB 에 NUL → 바이너리 판정, D01 존재 감지는 유지, D02 없음
    let root = common::temp_dir("t03-bin");
    fs::create_dir_all(root.join("vendor")).unwrap();
    fs::write(
        root.join("vendor").join("package.json"),
        [123u8, 0, 1, 2, 125],
    )
    .unwrap();
    let inv = inventory(
        vec![entry("vendor/package.json", EntryKind::File, Some("json"))],
        root.to_str().unwrap(),
    );
    let outcome = detect(&inv, &root).unwrap();

    assert_eq!(
        rule_paths(&outcome, RuleId::D01),
        vec!["vendor/package.json"]
    );
    assert!(rule_paths(&outcome, RuleId::D02).is_empty());
    assert_eq!(outcome.binary_skips, 1);
}
