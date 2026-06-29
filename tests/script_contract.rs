use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Checklist {
    families: Vec<CheckFamily>,
}

#[derive(Debug, Deserialize)]
struct CheckFamily {
    family: String,
    checks: Vec<ChecklistItem>,
}

#[derive(Debug, Deserialize)]
struct ChecklistItem {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ScriptInventory {
    scripts: Vec<ScriptEntry>,
}

#[derive(Debug, Deserialize)]
struct ScriptEntry {
    path: String,
    executable: bool,
    modules: Vec<ScriptModule>,
}

#[derive(Debug, Deserialize)]
struct ScriptModule {
    module_id: String,
    functions: Vec<String>,
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Traceability {
    module_checks: Vec<ModuleChecks>,
    final_verification: FinalVerification,
}

#[derive(Debug, Deserialize)]
struct ModuleChecks {
    module_id: String,
    script_path: String,
    check_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FinalVerification {
    check_ids: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_json<T: DeserializeOwned>(relative: &str) -> Result<T, Box<dyn Error>> {
    let text = fs::read_to_string(repo_root().join(relative))?;
    Ok(serde_json::from_str(&text)?)
}

#[test]
fn script_inventory_traceability_and_checklist_have_full_coverage() -> Result<(), Box<dyn Error>> {
    let checklist: Checklist = read_json("docs/script-verification/checklist.json")?;
    let inventory: ScriptInventory = read_json("docs/script-verification/script_inventory.json")?;
    let traceability: Traceability = read_json("docs/script-verification/traceability.json")?;

    let mut check_families = BTreeMap::new();
    for family in &checklist.families {
        assert!(
            !family.family.trim().is_empty(),
            "checklist family names must not be empty"
        );
        assert!(
            !family.checks.is_empty(),
            "checklist family {} must contain checks",
            family.family
        );
        for check in &family.checks {
            assert!(
                check_families
                    .insert(check.id.clone(), family.family.clone())
                    .is_none(),
                "duplicate checklist id {}",
                check.id
            );
        }
    }

    let mut inventory_scripts = BTreeSet::new();
    let mut inventory_modules = BTreeMap::new();
    for script in &inventory.scripts {
        assert!(
            script.executable,
            "{} must be marked executable in the script inventory",
            script.path
        );
        assert!(
            inventory_scripts.insert(script.path.clone()),
            "duplicate script inventory entry {}",
            script.path
        );
        assert!(
            !script.modules.is_empty(),
            "{} must be split into at least one module",
            script.path
        );
        for module in &script.modules {
            assert!(
                !module.functions.is_empty() || !module.commands.is_empty(),
                "{} must list owned functions or commands",
                module.module_id
            );
            assert!(
                inventory_modules
                    .insert(module.module_id.clone(), script.path.clone())
                    .is_none(),
                "duplicate module id {}",
                module.module_id
            );
        }
    }

    let mut actual_scripts = BTreeSet::new();
    for entry in fs::read_dir(repo_root().join("scripts"))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            actual_scripts.insert(format!("scripts/{}", entry.file_name().to_string_lossy()));
        }
    }
    assert_eq!(
        actual_scripts, inventory_scripts,
        "every script under scripts/ must be represented in script_inventory.json"
    );

    let mut traced_modules = BTreeSet::new();
    let mut covered_checks = BTreeSet::new();
    for module in &traceability.module_checks {
        let expected_script = inventory_modules.get(&module.module_id).ok_or_else(|| {
            invalid_data(format!(
                "traceability references unknown module {}",
                module.module_id
            ))
        })?;
        assert_eq!(
            expected_script, &module.script_path,
            "traceability script path mismatch for {}",
            module.module_id
        );
        assert!(
            traced_modules.insert(module.module_id.clone()),
            "duplicate traceability module {}",
            module.module_id
        );
        assert!(
            !module.check_ids.is_empty(),
            "{} must reference checklist IDs",
            module.module_id
        );

        let mut local_seen = BTreeSet::new();
        let mut has_req = false;
        let mut has_ui = false;
        let mut has_p0629 = false;
        for check_id in &module.check_ids {
            assert!(
                local_seen.insert(check_id.clone()),
                "{} has duplicate checklist id {}",
                module.module_id,
                check_id
            );
            let family = check_families.get(check_id).ok_or_else(|| {
                invalid_data(format!(
                    "{} references unknown checklist id {}",
                    module.module_id, check_id
                ))
            })?;
            has_req |= family == "REQ";
            has_ui |= family == "UI";
            has_p0629 |= family == "P0629";
            covered_checks.insert(check_id.clone());
        }
        assert!(
            has_req && has_ui && has_p0629,
            "{} must cover at least one REQ, one UI, and one P0629 checklist item",
            module.module_id
        );
    }

    let expected_modules = inventory_modules.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        traced_modules, expected_modules,
        "every inventory module must have a traceability entry"
    );

    for check_id in &traceability.final_verification.check_ids {
        assert!(
            check_families.contains_key(check_id),
            "final verification references unknown checklist id {}",
            check_id
        );
        covered_checks.insert(check_id.clone());
    }

    let all_checks = check_families.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        covered_checks, all_checks,
        "final meta-check requires every checklist item to be covered"
    );

    Ok(())
}

#[test]
fn hermes_script_enforces_cleanup_brief_and_no_target_package_manager_contracts(
) -> Result<(), Box<dyn Error>> {
    let script_path = repo_root().join("scripts/git-scv-hermes.sh");
    let script = fs::read_to_string(script_path)?;

    for required in [
        "--ack delete-git-scv-case",
        "--ack delete-all-git-scv-cases",
        ".git-scv-harness-case",
        "cleanup requires <case-dir> --ack delete-git-scv-case",
        "cleanup-all requires --ack delete-all-git-scv-cases",
        "cleanup) cleanup_cmd \"$@\" ;;",
        "cleanup-all) cleanup_all_cmd \"$@\" ;;",
        "artifact_manifest_json=$run_dir/artifact_manifest.json",
        "brief_json=$run_dir/brief.json",
        "brief_md=$run_dir/brief.md",
        "gates_json=$run_dir/gates.json",
        "connection_graph_json=$run_dir/connection_graph.json",
        "analysis_plan_json=$run_dir/analysis_plan.json",
        "cross_unit_analysis_json=$run_dir/cross_unit_analysis.json",
        "synthesis_json=$run_dir/synthesis.json",
        "followup_plan_json=$run_dir/followup_plan.json",
    ] {
        assert!(
            script.contains(required),
            "Hermes script contract string missing: {required}"
        );
    }

    assert!(
        script.matches("git-scv brief \"$run_dir\"").count() >= 2,
        "inspect and snapshot flows must print the mandatory brief"
    );

    for forbidden in [
        "npm install",
        "pip install",
        "brew install",
        "docker build",
        "docker run",
        "curl |",
        "eval ",
    ] {
        assert!(
            !script.contains(forbidden),
            "Hermes script must not contain target execution pattern `{forbidden}`"
        );
    }

    Ok(())
}
