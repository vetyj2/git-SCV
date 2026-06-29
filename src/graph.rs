//! Reachability graph and analysis plan generation.

use crate::model::{
    AnalysisPlanArtifact, AnalysisUnit, ConnectionGraphArtifact, CrossUnitTask, GateArtifact,
    GraphEdge, GraphNode, InventoryArtifact, ReachabilityScenario, SensitiveArtifact,
    SliceArtifact, SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn connection_graph(
    inventory: &InventoryArtifact,
    gates: &GateArtifact,
    slices: &SliceArtifact,
    run_id: &str,
) -> ConnectionGraphArtifact {
    let default_model_input = default_model_input_by_path(slices);
    let execution_paths = gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();
    let sensitive_paths = gates
        .sensitive_candidates
        .iter()
        .map(|item| item.path.as_str())
        .collect::<BTreeSet<_>>();

    let mut nodes = Vec::new();
    nodes.push(GraphNode {
        id: "gate:execution-command-review".into(),
        kind: "gate".into(),
        path: None,
        default_model_input: None,
        requires_execution_review: false,
        requires_user_approval: gates.execution_command_review.approval_required,
    });
    nodes.push(GraphNode {
        id: "gate:execution-model-input-review".into(),
        kind: "gate".into(),
        path: None,
        default_model_input: None,
        requires_execution_review: false,
        requires_user_approval: gates.execution_model_input_review.approval_required,
    });
    nodes.push(GraphNode {
        id: "gate:sensitive-raw-review".into(),
        kind: "gate".into(),
        path: None,
        default_model_input: None,
        requires_execution_review: false,
        requires_user_approval: gates.sensitive_raw_review.approval_required,
    });

    for entry in &inventory.entries {
        let path = entry.path.clone();
        nodes.push(GraphNode {
            id: format!("file:{path}"),
            kind: file_node_kind(
                &path,
                execution_paths.contains(path.as_str()),
                sensitive_paths.contains(path.as_str()),
            ),
            path: Some(path.clone()),
            default_model_input: default_model_input.get(path.as_str()).copied(),
            requires_execution_review: execution_paths.contains(path.as_str()),
            requires_user_approval: execution_paths.contains(path.as_str())
                || sensitive_paths.contains(path.as_str()),
        });
    }

    let mut edges = Vec::new();
    for path in &execution_paths {
        edges.push(GraphEdge {
            from: format!("file:{path}"),
            to: "gate:execution-command-review".into(),
            kind: "requires-user-approval".into(),
            execution_condition: None,
            approval_gate: Some("execution-command-review".into()),
        });
        edges.push(GraphEdge {
            from: format!("file:{path}"),
            to: "gate:execution-model-input-review".into(),
            kind: "excludes-from-model-input".into(),
            execution_condition: None,
            approval_gate: Some("execution-model-input-review".into()),
        });
    }
    for path in &sensitive_paths {
        edges.push(GraphEdge {
            from: format!("file:{path}"),
            to: "gate:sensitive-raw-review".into(),
            kind: "requires-user-approval".into(),
            execution_condition: None,
            approval_gate: Some("sensitive-raw-review".into()),
        });
    }

    let scenarios = scenarios(inventory, gates);
    ConnectionGraphArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        nodes,
        edges,
        scenarios,
    }
}

pub fn analysis_plan(
    inventory: &InventoryArtifact,
    gates: &GateArtifact,
    sensitive: &SensitiveArtifact,
    run_id: &str,
) -> AnalysisPlanArtifact {
    let mut units = Vec::new();
    let manifest_paths = inventory
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.path.as_str(),
                "package.json"
                    | "Cargo.toml"
                    | "Cargo.lock"
                    | "pyproject.toml"
                    | "setup.py"
                    | "go.mod"
                    | "Gemfile"
            )
        })
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    if !manifest_paths.is_empty() {
        units.push(AnalysisUnit {
            unit_id: "U0001".into(),
            kind: "manifest-analysis".into(),
            allowed_paths: manifest_paths,
            forbidden_paths: sensitive_paths(sensitive),
            questions: vec![
                "What install lifecycle or build surfaces exist?".into(),
                "What dependency source kinds appear?".into(),
                "Which graph nodes or edges need follow-up?".into(),
            ],
            depends_on_units: vec![],
        });
    }

    let execution_paths = gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
        .map(|item| item.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !execution_paths.is_empty() {
        units.push(AnalysisUnit {
            unit_id: format!("U{:04}", units.len() + 1),
            kind: "execution-surface-review".into(),
            allowed_paths: execution_paths,
            forbidden_paths: sensitive_paths(sensitive),
            questions: vec![
                "Which user actions make these execution surfaces reachable?".into(),
                "Which exact approvals are required before model input or execution?".into(),
            ],
            depends_on_units: vec![],
        });
    }

    let input_units = units
        .iter()
        .map(|unit| unit.unit_id.clone())
        .collect::<Vec<_>>();
    AnalysisPlanArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        units,
        cross_unit_tasks: vec![
            CrossUnitTask {
                task_id: "X0001".into(),
                kind: "install-path-synthesis".into(),
                input_units: input_units.clone(),
                questions: vec![
                    "What becomes reachable if the user runs the default install command?".into(),
                    "Are sensitive candidates adjacent to execution surfaces?".into(),
                    "Which gates remain unresolved?".into(),
                ],
                required_outputs: vec![
                    "reachable_execution_chain".into(),
                    "aggregate_risk_summary".into(),
                    "unresolved_edges".into(),
                    "followup_required".into(),
                ],
            },
            CrossUnitTask {
                task_id: "X0002".into(),
                kind: "architecture-visualization-synthesis".into(),
                input_units: vec!["*".into()],
                questions: vec![
                    "What architecture shape best describes this repository?".into(),
                    "Which visual views should be generated by default?".into(),
                    "Which source landmarks help a user understand the repository fastest?".into(),
                    "Which script relationships and execution scenarios must be highlighted?"
                        .into(),
                ],
                required_outputs: vec![
                    "architecture_map".into(),
                    "relation_map".into(),
                    "source_landmarks".into(),
                    "visualization_recommendations".into(),
                ],
            },
            CrossUnitTask {
                task_id: "X0003".into(),
                kind: "whole-repo-safety-diagnosis".into(),
                input_units,
                questions: vec![
                    "What cannot be concluded from observed scope?".into(),
                    "Which user actions remain blocked?".into(),
                ],
                required_outputs: vec![
                    "required_user_actions".into(),
                    "what_cannot_be_concluded".into(),
                ],
            },
        ],
    }
}

fn default_model_input_by_path(slices: &SliceArtifact) -> BTreeMap<&str, bool> {
    let mut map = BTreeMap::new();
    for file in slices.slices.iter().flat_map(|slice| slice.files.iter()) {
        map.insert(file.path.as_str(), file.default_model_input);
    }
    map
}

fn file_node_kind(path: &str, execution: bool, sensitive: bool) -> String {
    if sensitive {
        "sensitive-candidate".into()
    } else if execution {
        "execution-related-file".into()
    } else if path.ends_with("package.json") {
        "manifest".into()
    } else {
        "file".into()
    }
}

fn scenarios(inventory: &InventoryArtifact, gates: &GateArtifact) -> Vec<ReachabilityScenario> {
    let paths = inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let execution_nodes = gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
        .map(|item| format!("file:{}", item.path))
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    if paths.contains("package.json") {
        out.push(scenario(
            "S-install-npm",
            "npm install",
            ["file:package.json".into()]
                .into_iter()
                .chain(execution_nodes.clone())
                .collect(),
            gates.execution_command_review.approval_required,
        ));
    }
    if paths.contains(".vscode/tasks.json") {
        out.push(scenario(
            "S-open-vscode",
            "open folder in VS Code",
            vec!["file:.vscode/tasks.json".into()],
            gates.execution_model_input_review.approval_required,
        ));
    }
    if paths.contains(".husky") {
        out.push(scenario(
            "S-git-commit-hooks",
            "git commit with hooks",
            vec!["file:.husky".into()],
            gates.execution_command_review.approval_required,
        ));
    }
    if paths.contains("Dockerfile") {
        out.push(scenario(
            "S-docker-build",
            "docker build",
            vec!["file:Dockerfile".into()],
            gates.execution_command_review.approval_required,
        ));
    }
    if paths.contains("Makefile") {
        out.push(scenario(
            "S-make",
            "make",
            vec!["file:Makefile".into()],
            gates.execution_command_review.approval_required,
        ));
    }
    out
}

fn scenario(
    scenario_id: &str,
    user_action: &str,
    reachable_nodes: Vec<String>,
    blocked: bool,
) -> ReachabilityScenario {
    ReachabilityScenario {
        scenario_id: scenario_id.into(),
        user_action: user_action.into(),
        reachable_nodes,
        blocked_by: if blocked {
            vec!["execution-command-review".into()]
        } else {
            vec![]
        },
        safe_to_execute_without_user: false,
    }
}

fn sensitive_paths(sensitive: &SensitiveArtifact) -> Vec<String> {
    sensitive
        .candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect()
}
