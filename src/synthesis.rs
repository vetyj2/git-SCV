//! Minimal cross-unit synthesis from first-party Git-SCV artifacts.

use crate::model::{
    AggregatePath, AggregateSafetyDiagnosis, AnalysisStage, ArchitectureMapArtifact,
    ArchitectureSynthesis, ConnectionGraphArtifact, CoverageArtifact, CrossUnitAnalysisArtifact,
    FollowupItem, FollowupPlanArtifact, GateArtifact, ReviewArtifact, SourceLandmarksArtifact,
    SynergyFinding, SynthesisArtifact, SCHEMA_VERSION,
};

pub fn cross_unit_analysis(
    graph: &ConnectionGraphArtifact,
    gates: &GateArtifact,
    review: &ReviewArtifact,
    run_id: &str,
) -> CrossUnitAnalysisArtifact {
    let aggregate_paths = graph
        .scenarios
        .iter()
        .map(|scenario| AggregatePath {
            scenario: scenario.user_action.clone(),
            reachable_nodes: scenario.reachable_nodes.clone(),
            blocked_by_gates: scenario.blocked_by.clone(),
            risk_summary: if scenario.blocked_by.is_empty() {
                "No Git-SCV gate is attached to this scenario within observed scope.".into()
            } else {
                format!(
                    "Scenario is blocked by gates: {}.",
                    scenario.blocked_by.join(", ")
                )
            },
            safe_to_execute_without_user: false,
        })
        .collect::<Vec<_>>();

    let mut synergy_findings = Vec::new();
    if !gates.sensitive_candidates.is_empty()
        && (!gates.automatic_execution_candidates.is_empty()
            || !gates.execution_related_candidates.is_empty())
    {
        synergy_findings.push(SynergyFinding {
            id: "SYN001".into(),
            kind: "sensitive-plus-execution".into(),
            summary: "Sensitive candidates and execution-related candidates both appear in the observed repository surface.".into(),
            requires_followup: true,
        });
    }
    let followup_required = review.required_actions.iter().any(|action| action.required)
        || synergy_findings
            .iter()
            .any(|finding| finding.requires_followup);

    CrossUnitAnalysisArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        analysis_stage: AnalysisStage::StaticPreflightOnly,
        input_units: vec!["analysis_plan.units".into()],
        aggregate_paths,
        synergy_findings,
        conflicts: Vec::new(),
        unresolved_edges: Vec::new(),
        followup_required,
    }
}

pub fn synthesis(
    review: &ReviewArtifact,
    coverage: &CoverageArtifact,
    gates: &GateArtifact,
    cross: &CrossUnitAnalysisArtifact,
    architecture: &ArchitectureMapArtifact,
    landmarks: &SourceLandmarksArtifact,
    run_id: &str,
) -> SynthesisArtifact {
    let required_user_actions = review
        .required_actions
        .iter()
        .filter(|action| action.required)
        .map(|action| action.id.clone())
        .collect::<Vec<_>>();
    let blocked_execution_surfaces = gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let mut insufficient_coverage_reasons = coverage.limit_reason_codes.clone();
    insufficient_coverage_reasons.extend(
        review
            .reason_codes
            .iter()
            .filter(|code| {
                code.as_str() == "unsupported-surface-name-detected"
                    || code.ends_with("-limit-exceeded")
                    || code.ends_with("-coverage")
            })
            .cloned(),
    );
    insufficient_coverage_reasons.sort();
    insufficient_coverage_reasons.dedup();

    SynthesisArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        analysis_stage: AnalysisStage::StaticPreflightOnly,
        synthesis_kind: "static-preflight-summary".into(),
        verdict: review.verdict.clone(),
        safe_claim_made: false,
        unit_analyses_complete: false,
        cross_unit_analysis_complete: "minimal-static".into(),
        architecture_visualization_complete: true,
        source_fingerprint_verified: false,
        unresolved_edges_count: cross.unresolved_edges.len() as u64,
        conflicts_count: cross.conflicts.len() as u64,
        required_user_actions,
        architecture_synthesis: ArchitectureSynthesis {
            detected_shapes: architecture.repo_shape.detected_shapes.clone(),
            primary_sectors: architecture
                .sectors
                .iter()
                .map(|sector| sector.name.clone())
                .collect(),
            recommended_visualization: "architecture.html".into(),
            source_landmarks_available: !landmarks.recommended_reading_order.is_empty(),
        },
        aggregate_safety_diagnosis: AggregateSafetyDiagnosis {
            no_blocker_observed_within_scope: review.verdict == "no-blocker-observed",
            blocked_execution_surfaces,
            insufficient_coverage_reasons,
            what_cannot_be_concluded: vec![
                "Absence of malware cannot be proven.".into(),
                "Install, build, test, and run safety is not guaranteed.".into(),
                "Transitive dependency source code was not fully evaluated.".into(),
                "Unit-level semantic truth was not validated by Git-SCV.".into(),
            ],
        },
    }
}

pub fn followup_plan(
    review: &ReviewArtifact,
    cross: &CrossUnitAnalysisArtifact,
    run_id: &str,
) -> FollowupPlanArtifact {
    let mut required_followups = Vec::new();
    for action in review
        .required_actions
        .iter()
        .filter(|action| action.required)
    {
        required_followups.push(FollowupItem {
            followup_id: format!("F{:04}", required_followups.len() + 1),
            kind: "resolve-gate".into(),
            needed_artifacts: vec![
                "brief.json".into(),
                "gates.json".into(),
                "connection_graph.json".into(),
            ],
            needed_user_approval: Some(action.id.clone()),
            question: format!(
                "Resolve required gate {} without exposing raw secrets or running target commands.",
                action.id
            ),
        });
    }
    if cross.followup_required && required_followups.is_empty() {
        required_followups.push(FollowupItem {
            followup_id: "F0001".into(),
            kind: "review-synergy".into(),
            needed_artifacts: vec!["cross_unit_analysis.json".into()],
            needed_user_approval: None,
            question: "Review combined-risk findings before claiming no blocker observed.".into(),
        });
    }

    FollowupPlanArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        analysis_stage: AnalysisStage::StaticPreflightOnly,
        round: 1,
        reason: if required_followups.is_empty() {
            "no-followup-required-within-current-static-scope".into()
        } else {
            "required gates or combined-risk findings remain unresolved".into()
        },
        required_followups,
        blocked_until: if review.required_actions.iter().any(|action| action.required) {
            vec![
                "user_gate_decision".into(),
                "source_verify_before_execution".into(),
            ]
        } else {
            vec!["source_verify_before_execution".into()]
        },
    }
}
