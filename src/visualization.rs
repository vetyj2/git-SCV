//! Architecture and visualization artifacts.
//!
//! This module only consumes already-built Git-SCV artifacts. It never reads
//! target repository files and never executes target content.

use crate::errors::ScvError;
use crate::model::{
    ArchitectureEntrypoint, ArchitectureMapArtifact, ArchitectureSector, ArchitectureSummary,
    ConnectionGraphArtifact, CoverageArtifact, DependencyArtifact, GateArtifact,
    GateDecisionArtifact, InventoryArtifact, ReachabilityScenariosArtifact, Relation,
    RelationMapArtifact, RepoShape, SectorsArtifact, SensitiveArtifact, SourceArtifact,
    SourceLandmark, SourceLandmarkGuard, SourceLandmarksArtifact, SupportedSurfacesArtifact,
    VisualizationGraphLimits, VisualizationIndexArtifact, VisualizationPrivacy, VisualizationView,
    SCHEMA_VERSION,
};
use serde_json::json;
use std::collections::BTreeSet;

const BASIC_MAX_NODES: usize = 200;
const BASIC_MAX_EDGES: usize = 300;

pub fn supported_surfaces(coverage: &CoverageArtifact, run_id: &str) -> SupportedSurfacesArtifact {
    SupportedSurfacesArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        capabilities: coverage.capabilities.clone(),
        note: "Capability matrix for parsed, name-detected, unsupported, or parse-failed repository surfaces. Raw values are not stored.".into(),
    }
}

pub fn gate_decisions(source: &SourceArtifact, run_id: &str) -> GateDecisionArtifact {
    GateDecisionArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        source_fingerprint_hash: source_fingerprint_hash(source),
        artifact_manifest_sha256_required: true,
        expires_on_source_change: true,
        decisions: Vec::new(),
        note: "No gate decisions are created automatically. Any future decision must bind to source fingerprint, artifact manifest, exact path/action, and exact acknowledgement.".into(),
    }
}

pub fn reachability_scenarios(
    graph: &ConnectionGraphArtifact,
    run_id: &str,
) -> ReachabilityScenariosArtifact {
    ReachabilityScenariosArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        scenarios: graph.scenarios.clone(),
        note: "User-action reachability scenarios are static pre-execution analysis and do not authorize running target commands.".into(),
    }
}

pub fn architecture_map(
    inventory: &InventoryArtifact,
    coverage: &CoverageArtifact,
    gates: &GateArtifact,
    dependencies: &DependencyArtifact,
    sectors: &SectorsArtifact,
    run_id: &str,
) -> ArchitectureMapArtifact {
    let shapes = detected_shapes(inventory, coverage, dependencies);
    let low_confidence =
        coverage.capabilities.iter().any(|capability| {
            capability.verdict_effect.as_deref() == Some("insufficient-coverage")
        }) || shapes.iter().any(|shape| shape == "unknown-mixed");
    let confidence = if low_confidence { "low" } else { "medium" };
    let limitations = coverage
        .capabilities
        .iter()
        .filter(|capability| capability.verdict_effect.is_some())
        .map(|capability| {
            format!(
                "{} is {} and affects verdict as {}",
                capability.surface,
                capability.support,
                capability.verdict_effect.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>();
    let architecture_sectors = sectors
        .sectors
        .iter()
        .enumerate()
        .take(12)
        .map(|(index, sector)| ArchitectureSector {
            sector_id: format!("SEC{:04}", index + 1),
            name: sector.name.clone(),
            paths: sectors
                .suggested_read_order
                .iter()
                .filter(|path| sector_matches_path(&sector.name, path))
                .take(12)
                .cloned()
                .collect(),
            primary_role: sector_role(&sector.name),
            model_input_status: "path-plan-see-slices-json".into(),
            gate_status: gate_status_for_sector(&sector.name, gates),
        })
        .collect::<Vec<_>>();
    let entrypoints = entrypoints(inventory, gates);
    let summary = ArchitectureSummary {
        human_summary: architecture_summary_text(&shapes, gates, coverage),
        safe_claim_made: false,
    };
    ArchitectureMapArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        repo_shape: RepoShape {
            detected_shapes: shapes.clone(),
            confidence: confidence.into(),
            limitations,
        },
        sectors: architecture_sectors,
        entrypoints,
        architecture_summary: summary,
        visualization_recommendations: recommended_views(&shapes),
    }
}

pub fn relation_map(graph: &ConnectionGraphArtifact, run_id: &str) -> RelationMapArtifact {
    let mut relations = Vec::new();
    for edge in &graph.edges {
        relations.push(Relation {
            relation_id: format!("REL{:04}", relations.len() + 1),
            from: edge.from.clone(),
            to: edge.to.clone(),
            kind: edge.kind.clone(),
            confidence: if edge.approval_gate.is_some() {
                "high".into()
            } else {
                "medium".into()
            },
            evidence_refs: Vec::new(),
            blocked_by: edge
                .approval_gate
                .as_ref()
                .map(|gate| vec![gate.clone()])
                .unwrap_or_default(),
            unresolved: edge.kind.contains("unknown"),
        });
    }
    for scenario in &graph.scenarios {
        for node in &scenario.reachable_nodes {
            let relation_kind = if scenario.scenario_id.contains("install") {
                "install-lifecycle"
            } else if scenario.scenario_id.contains("make") {
                "build-lifecycle"
            } else if scenario.scenario_id.contains("git-commit") {
                "hook-lifecycle"
            } else {
                "reachable-under-scenario"
            };
            relations.push(Relation {
                relation_id: format!("REL{:04}", relations.len() + 1),
                from: format!("scenario:{}", scenario.scenario_id),
                to: node.clone(),
                kind: relation_kind.into(),
                confidence: "high".into(),
                evidence_refs: Vec::new(),
                blocked_by: scenario.blocked_by.clone(),
                unresolved: false,
            });
        }
    }
    let unresolved_relations = relations
        .iter()
        .filter(|relation| relation.unresolved)
        .map(|relation| crate::model::UnresolvedRelation {
            relation_id: relation.relation_id.clone(),
            reason: "Relation target is unresolved within current static analysis scope.".into(),
        })
        .collect::<Vec<_>>();
    RelationMapArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        relations,
        unresolved_relations,
    }
}

pub fn source_landmarks(
    sectors: &SectorsArtifact,
    gates: &GateArtifact,
    sensitive: &SensitiveArtifact,
    run_id: &str,
) -> SourceLandmarksArtifact {
    let mut recommended = vec![
        SourceLandmark {
            rank: 1,
            path: "brief.md".into(),
            why: "Mandatory one-screen safety and actionability summary.".into(),
            model_input_status: Some("artifact".into()),
        },
        SourceLandmark {
            rank: 2,
            path: "architecture.html".into(),
            why: "Interactive repository structure, reachability, gate, and synthesis overview."
                .into(),
            model_input_status: Some("artifact".into()),
        },
    ];
    for path in sectors.suggested_read_order.iter().take(18) {
        recommended.push(SourceLandmark {
            rank: recommended.len() as u64 + 1,
            path: path.clone(),
            why: "Suggested static review path from sector ordering.".into(),
            model_input_status: Some("see-slices-json".into()),
        });
    }
    let do_not_read_by_default = sensitive
        .candidates
        .iter()
        .map(|candidate| SourceLandmarkGuard {
            path: candidate.path.clone(),
            reason: "Sensitive candidate; raw content excluded by default.".into(),
        })
        .collect::<Vec<_>>();
    let gate_before_reading = gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
        .map(|item| SourceLandmarkGuard {
            path: item.path.clone(),
            reason: "Execution-related path; model-input review required before raw body analysis."
                .into(),
        })
        .collect::<Vec<_>>();
    SourceLandmarksArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        recommended_reading_order: recommended,
        do_not_read_by_default,
        gate_before_reading,
    }
}

pub fn visualization_index(
    graph: &ConnectionGraphArtifact,
    run_id: &str,
) -> VisualizationIndexArtifact {
    VisualizationIndexArtifact {
        schema_version: SCHEMA_VERSION.into(),
        run_id: run_id.into(),
        default_visualization: "architecture.html".into(),
        views: vec![
            view(
                "overview",
                "Repository Overview",
                &["architecture_map.json", "source_landmarks.json"],
            ),
            view(
                "execution-scenarios",
                "Execution Scenario Reachability",
                &["reachability_scenarios.json", "connection_graph.json"],
            ),
            view(
                "script-relations",
                "Script and Hook Relationships",
                &["relation_map.json", "connection_graph.json"],
            ),
            view(
                "security-gates",
                "Sensitive and Execution Gates",
                &["gates.json", "sensitive.json", "review.json"],
            ),
            view(
                "synthesis",
                "Architecture and Safety Synthesis",
                &[
                    "cross_unit_analysis.json",
                    "synthesis.json",
                    "followup_plan.json",
                ],
            ),
        ],
        privacy: VisualizationPrivacy {
            raw_sensitive_content_included: false,
            target_repo_js_executed: false,
            external_network_required: false,
        },
        graph_limits: VisualizationGraphLimits {
            max_nodes: BASIC_MAX_NODES as u64,
            max_edges: BASIC_MAX_EDGES as u64,
            truncated: graph.nodes.len() > BASIC_MAX_NODES || graph.edges.len() > BASIC_MAX_EDGES,
        },
    }
}

pub fn render_architecture_html(data: &crate::model::RunData) -> Result<String, ScvError> {
    let view_data = json!({
        "run_id": data.run_id,
        "source_fingerprint_hash": source_fingerprint_hash(&data.source),
        "verdict": data.review.verdict,
        "safe_claim_made": false,
        "action_required": data.review.required_actions.iter().any(|action| action.required),
        "architecture_map": data.architecture_map,
        "relation_map": data.relation_map,
        "source_landmarks": data.source_landmarks,
        "visualization_index": data.visualization_index,
        "reachability_scenarios": data.reachability_scenarios,
        "supported_surfaces": data.supported_surfaces,
        "gates": data.gates,
        "review": data.review,
        "synthesis": data.synthesis,
        "followup_plan": data.followup_plan,
    });
    let data_json = safe_embedded_json(&view_data)?;
    Ok(format!(
        r#"<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Git-SCV Architecture</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #18202f;
      --muted: #647084;
      --line: #d8dee8;
      --accent: #0f766e;
      --blocked: #b42318;
      --warn: #a15c07;
      --ok: #287a3e;
      --chip: #eef3f8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }}
    header {{
      padding: 20px 24px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    h1, h2, h3 {{ margin: 0; letter-spacing: 0; }}
    h1 {{ font-size: 22px; }}
    h2 {{ font-size: 17px; margin-bottom: 10px; }}
    h3 {{ font-size: 14px; margin-bottom: 6px; }}
    main {{
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 16px;
      padding: 16px;
    }}
    aside, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    aside {{ align-self: start; position: sticky; top: 88px; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
    }}
    .label {{ color: var(--muted); font-size: 12px; }}
    .value {{ font-weight: 700; overflow-wrap: anywhere; }}
    .tabs {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
    button {{
      border: 1px solid var(--line);
      background: var(--chip);
      color: var(--text);
      border-radius: 8px;
      padding: 8px 10px;
      cursor: pointer;
      font: inherit;
    }}
    button.active {{ background: var(--accent); color: white; border-color: var(--accent); }}
    input, select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
      font: inherit;
      margin: 6px 0 10px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 10px;
    }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
      overflow-wrap: anywhere;
    }}
    .chips {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
    .chip {{ background: var(--chip); border-radius: 999px; padding: 4px 8px; font-size: 12px; }}
    .blocked {{ color: var(--blocked); }}
    .warn {{ color: var(--warn); }}
    .ok {{ color: var(--ok); }}
    .view {{ display: none; }}
    .view.active {{ display: block; }}
    .graph {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 8px;
    }}
    .node {{ border-left: 4px solid var(--accent); }}
    .edge {{ border-left: 4px solid var(--warn); }}
    ul {{ margin: 8px 0 0; padding-left: 18px; }}
    li + li {{ margin-top: 6px; }}
    @media (max-width: 860px) {{
      main {{ grid-template-columns: 1fr; }}
      aside {{ position: static; }}
    }}
    @media print {{
      header, aside {{ position: static; }}
      button, input, select {{ display: none; }}
      .view {{ display: block; break-inside: avoid; margin-bottom: 12px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Git-SCV Architecture & Safety Synthesis</h1>
    <div class="summary" id="summary"></div>
    <div class="tabs" id="tabs"></div>
  </header>
  <main>
    <aside>
      <h2>Filters</h2>
      <label class="label" for="search">Search path, node, scenario</label>
      <input id="search" placeholder="package.json, install, gate">
      <label class="label" for="kindFilter">Node kind</label>
      <select id="kindFilter"><option value="">All node kinds</option></select>
      <label class="label" for="gateFilter">Gate status</label>
      <select id="gateFilter">
        <option value="">All</option>
        <option value="blocked">Blocked</option>
        <option value="ungated">No gate attached</option>
      </select>
      <div class="card">
        <strong>No raw content included</strong>
        <p>raw content not included</p>
        <p>Target repository commands, sensitive raw content, and target HTML/JS are not executed or embedded.</p>
      </div>
    </aside>
    <div id="views"></div>
  </main>
  <script id="git-scv-data" type="application/json">{data_json}</script>
  <script>
    const data = JSON.parse(document.getElementById('git-scv-data').textContent);
    const state = {{ view: 'overview', search: '', kind: '', gate: '' }};
    const views = [
      ['overview', 'Overview'],
      ['execution-scenarios', 'Scenarios'],
      ['script-relations', 'Relations'],
      ['security-gates', 'Gates'],
      ['coverage-unknowns', 'Coverage'],
      ['source-landmarks', 'Landmarks'],
      ['synthesis', 'Synthesis']
    ];
    const text = value => String(value ?? '');
    const esc = value => text(value).replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
    const includes = (value) => text(value).toLowerCase().includes(state.search.toLowerCase());
    function card(title, lines, cls = '') {{
      return `<div class="card ${{cls}}"><h3>${{esc(title)}}</h3>${{lines.map(line => `<div>${{esc(line)}}</div>`).join('')}}</div>`;
    }}
    function chips(items) {{
      return `<div class="chips">${{items.map(item => `<span class="chip">${{esc(item)}}</span>`).join('')}}</div>`;
    }}
    function renderSummary() {{
      const arch = data.architecture_map;
      const synth = data.synthesis;
      const blocked = (data.review.required_actions || []).filter(a => a.required).map(a => a.id);
      document.getElementById('summary').innerHTML = [
        ['Verdict', data.verdict, 'blocked'],
        ['Safe claim made', String(data.safe_claim_made), data.safe_claim_made ? 'blocked' : 'ok'],
        ['Repo shape', (arch.repo_shape.detected_shapes || []).join(', ') || 'unknown', ''],
        ['Blocked actions', blocked.join(', ') || 'none', blocked.length ? 'blocked' : 'ok'],
        ['Unresolved edges', String(synth.unresolved_edges_count || 0), synth.unresolved_edges_count ? 'warn' : 'ok'],
        ['Source fingerprint', data.source_fingerprint_hash, '']
      ].map(([label, value, cls]) => `<div class="metric"><div class="label">${{esc(label)}}</div><div class="value ${{cls}}">${{esc(value)}}</div></div>`).join('');
    }}
    function renderTabs() {{
      document.getElementById('tabs').innerHTML = views.map(([id, label]) => `<button data-view="${{id}}" class="${{state.view === id ? 'active' : ''}}">${{esc(label)}}</button>`).join('');
      document.querySelectorAll('[data-view]').forEach(btn => btn.onclick = () => {{ state.view = btn.dataset.view; render(); }});
    }}
    function renderFilters() {{
      const kinds = [...new Set((data.reachability_scenarios.scenarios || []).flatMap(s => s.reachable_nodes || []).concat((data.relation_map.relations || []).flatMap(r => [r.from, r.to])).map(id => id.split(':')[0]).filter(Boolean))].sort();
      const select = document.getElementById('kindFilter');
      select.innerHTML = '<option value="">All node kinds</option>' + kinds.map(kind => `<option value="${{esc(kind)}}">${{esc(kind)}}</option>`).join('');
      select.value = state.kind;
    }}
    function passesGate(item) {{
      if (!state.gate) return true;
      const blocked = (item.blocked_by || item.blocked_by_gates || []).length > 0;
      return state.gate === 'blocked' ? blocked : !blocked;
    }}
    function renderOverview() {{
      const arch = data.architecture_map;
      return `<section class="view active"><h2>Overview Map</h2>
        <div class="grid">
          ${{card('Architecture summary', [arch.architecture_summary.human_summary, `confidence: ${{arch.repo_shape.confidence}}`])}}
          ${{card('Detected shapes', arch.repo_shape.detected_shapes || [])}}
          ${{card('Recommended views', arch.visualization_recommendations || [])}}
          ${{card('Coverage limitations', arch.repo_shape.limitations?.length ? arch.repo_shape.limitations : ['none recorded'])}}
        </div>
        <h2>Main sectors</h2><div class="grid">${{(arch.sectors || []).map(s => card(s.name, [s.primary_role, `gate: ${{s.gate_status}}`, `model input: ${{s.model_input_status}}`])).join('')}}</div>
      </section>`;
    }}
    function renderScenarios() {{
      const scenarios = (data.reachability_scenarios.scenarios || []).filter(s => (!state.search || includes(s.user_action) || includes((s.reachable_nodes || []).join(' '))) && passesGate(s));
      return `<section class="view active"><h2>Execution Scenario Reachability</h2><div class="grid">${{scenarios.map(s => card(s.user_action, [`id: ${{s.scenario_id}}`, `blocked_by: ${{(s.blocked_by || []).join(', ') || 'none'}}`, `safe_to_execute_without_user: ${{s.safe_to_execute_without_user}}`]).replace('</div>', `${{chips(s.reachable_nodes || [])}}</div>`)).join('')}}</div></section>`;
    }}
    function renderRelations() {{
      const relations = (data.relation_map.relations || []).filter(r => (!state.search || includes(r.from) || includes(r.to) || includes(r.kind)) && (!state.kind || r.from.startsWith(state.kind + ':') || r.to.startsWith(state.kind + ':')) && passesGate(r));
      return `<section class="view active"><h2>Script Relationship View</h2><div class="graph">${{relations.map(r => card(`${{r.from}} -> ${{r.to}}`, [`kind: ${{r.kind}}`, `confidence: ${{r.confidence}}`, `blocked_by: ${{(r.blocked_by || []).join(', ') || 'none'}}`, `unresolved: ${{r.unresolved}}`], 'edge')).join('')}}</div></section>`;
    }}
    function renderGates() {{
      const gates = data.gates;
      return `<section class="view active"><h2>Security Gate Overlay</h2><div class="grid">
        ${{card('Sensitive raw review', [`required: ${{gates.sensitive_raw_review.approval_required}}`, `paths: ${{gates.sensitive_raw_review.paths.length}}`, `ack: ${{gates.sensitive_raw_review.acknowledgements.join(', ')}}`])}}
        ${{card('Execution model-input review', [`required: ${{gates.execution_model_input_review.approval_required}}`, `paths: ${{gates.execution_model_input_review.paths.length}}`, `ack: ${{gates.execution_model_input_review.acknowledgements.join(', ')}}`])}}
        ${{card('Execution command review', [`required: ${{gates.execution_command_review.approval_required}}`, `requires_exact_command: ${{gates.execution_command_review.requires_exact_command}}`, `ack: ${{gates.execution_command_review.acknowledgements.join(', ')}}`])}}
      </div></section>`;
    }}
    function renderCoverage() {{
      const caps = data.supported_surfaces.capabilities || [];
      return `<section class="view active"><h2>Coverage / Unknowns</h2><div class="grid">${{caps.map(c => card(c.surface, [`support: ${{c.support}}`, `signals: ${{(c.signals || []).join(', ')}}`, `verdict_effect: ${{c.verdict_effect || 'none'}}`, `raw_values_stored: ${{c.raw_values_stored}}`])).join('')}}</div></section>`;
    }}
    function renderLandmarks() {{
      const landmarks = data.source_landmarks;
      return `<section class="view active"><h2>Source Landmarks</h2><div class="grid">
        ${{(landmarks.recommended_reading_order || []).map(l => card(`${{l.rank}}. ${{l.path}}`, [l.why, `model input: ${{l.model_input_status || 'unknown'}}`])).join('')}}
      </div><h2>Gate before reading</h2><div class="grid">${{(landmarks.gate_before_reading || []).map(l => card(l.path, [l.reason], 'node')).join('')}}</div></section>`;
    }}
    function renderSynthesis() {{
      const synth = data.synthesis;
      const diag = synth.aggregate_safety_diagnosis;
      return `<section class="view active"><h2>Synthesis View</h2><div class="grid">
        ${{card('Architecture synthesis', [`shapes: ${{(synth.architecture_synthesis.detected_shapes || []).join(', ')}}`, `primary sectors: ${{(synth.architecture_synthesis.primary_sectors || []).join(', ')}}`, `visualization: ${{synth.architecture_synthesis.recommended_visualization}}`])}}
        ${{card('Aggregate safety diagnosis', [`no_blocker_observed_within_scope: ${{diag.no_blocker_observed_within_scope}}`, `blocked surfaces: ${{(diag.blocked_execution_surfaces || []).join(', ') || 'none'}}`, `insufficient coverage: ${{(diag.insufficient_coverage_reasons || []).join(', ') || 'none'}}`])}}
        ${{card('What cannot be concluded', diag.what_cannot_be_concluded || [])}}
      </div></section>`;
    }}
    function renderViews() {{
      const byId = {{
        'overview': renderOverview,
        'execution-scenarios': renderScenarios,
        'script-relations': renderRelations,
        'security-gates': renderGates,
        'coverage-unknowns': renderCoverage,
        'source-landmarks': renderLandmarks,
        'synthesis': renderSynthesis
      }};
      document.getElementById('views').innerHTML = byId[state.view]();
    }}
    function render() {{ renderSummary(); renderTabs(); renderFilters(); renderViews(); }}
    document.getElementById('search').oninput = e => {{ state.search = e.target.value; renderViews(); }};
    document.getElementById('kindFilter').onchange = e => {{ state.kind = e.target.value; renderViews(); }};
    document.getElementById('gateFilter').onchange = e => {{ state.gate = e.target.value; renderViews(); }};
    render();
  </script>
</body>
</html>
"#,
        data_json = data_json,
    ))
}

pub fn source_fingerprint_hash(source: &SourceArtifact) -> String {
    source
        .source_fingerprint
        .as_ref()
        .map(|fingerprint| fingerprint.fingerprint_hash.clone())
        .unwrap_or_else(|| "sha256:unknown".into())
}

fn view(view_id: &str, title: &str, source_artifacts: &[&str]) -> VisualizationView {
    VisualizationView {
        view_id: view_id.into(),
        title: title.into(),
        source_artifacts: source_artifacts.iter().map(|item| (*item).into()).collect(),
    }
}

fn detected_shapes(
    inventory: &InventoryArtifact,
    coverage: &CoverageArtifact,
    dependencies: &DependencyArtifact,
) -> Vec<String> {
    let paths = inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut shapes = Vec::new();
    if paths.contains("package.json") {
        shapes.push("npm-package".into());
    }
    if paths.contains("Cargo.toml") {
        shapes.push("rust-project".into());
    }
    if paths.contains("Dockerfile") || paths.contains("docker-compose.yml") {
        shapes.push("containerized-app".into());
    }
    if paths
        .iter()
        .any(|path| path.starts_with(".github/workflows/"))
    {
        shapes.push("github-actions-heavy".into());
    }
    if dependencies.manifests.len() > 1 {
        shapes.push("multi-package".into());
    }
    if coverage.capabilities.iter().any(|capability| {
        capability.surface.contains("shell") || capability.surface.contains("Makefile")
    }) {
        shapes.push("script-collection".into());
    }
    if shapes.is_empty() {
        shapes.push("unknown-mixed".into());
    }
    shapes.sort();
    shapes.dedup();
    shapes
}

fn sector_matches_path(sector_name: &str, path: &str) -> bool {
    match sector_name {
        "manifest" => {
            matches!(
                path,
                "package.json" | "Cargo.toml" | "Cargo.lock" | "pyproject.toml" | "go.mod"
            )
        }
        "automation" => {
            path.ends_with(".sh")
                || path == "Makefile"
                || path == "Dockerfile"
                || path.starts_with(".github/workflows/")
        }
        "sensitive" => path.contains("secret") || path.contains(".env"),
        _ => true,
    }
}

fn sector_role(sector_name: &str) -> String {
    match sector_name {
        "manifest" => "Defines package metadata, dependencies, and lifecycle surfaces.".into(),
        "automation" => "Contains scripts, hooks, workflows, build, or container surfaces.".into(),
        "sensitive" => {
            "Contains sensitive-looking paths excluded from raw default model input.".into()
        }
        _ => "Source files or supporting repository content in the observed inventory.".into(),
    }
}

fn gate_status_for_sector(sector_name: &str, gates: &GateArtifact) -> String {
    if sector_name == "sensitive" && gates.sensitive_raw_review.approval_required {
        "sensitive-raw-review-required".into()
    } else if sector_name == "automation"
        && (gates.execution_command_review.approval_required
            || gates.execution_model_input_review.approval_required)
    {
        "execution-review-required".into()
    } else {
        "no-sector-gate-observed".into()
    }
}

fn entrypoints(inventory: &InventoryArtifact, gates: &GateArtifact) -> Vec<ArchitectureEntrypoint> {
    let paths = inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    if paths.contains("package.json") {
        out.push(ArchitectureEntrypoint {
            id: "EP0001".into(),
            kind: "package-manifest".into(),
            name: "package.json".into(),
            path: "package.json".into(),
            reachable_under: vec!["npm install".into(), "npm test".into()],
            blocked_by: if gates.execution_command_review.approval_required {
                vec!["execution-command-review".into()]
            } else {
                Vec::new()
            },
        });
    }
    for item in gates
        .automatic_execution_candidates
        .iter()
        .chain(gates.execution_related_candidates.iter())
    {
        out.push(ArchitectureEntrypoint {
            id: format!("EP{:04}", out.len() + 1),
            kind: item.rule.clone(),
            name: item.rule.clone(),
            path: item.path.clone(),
            reachable_under: vec!["see-reachability-scenarios".into()],
            blocked_by: vec!["execution-command-review".into()],
        });
    }
    out
}

fn architecture_summary_text(
    shapes: &[String],
    gates: &GateArtifact,
    coverage: &CoverageArtifact,
) -> String {
    let shape_text = if shapes.is_empty() {
        "unknown repository shape".into()
    } else {
        shapes.join(", ")
    };
    let gate_text = if gates.execution_command_review.approval_required
        || gates.sensitive_raw_review.approval_required
    {
        "required gates are present"
    } else {
        "no required gate was observed within current static scope"
    };
    let coverage_text = if coverage
        .capabilities
        .iter()
        .any(|capability| capability.verdict_effect.is_some())
    {
        "coverage limitations are present"
    } else {
        "no coverage limitation was recorded"
    };
    format!("This repository appears to have shape(s): {shape_text}; {gate_text}; {coverage_text}. This is not a safety claim.")
}

fn recommended_views(shapes: &[String]) -> Vec<String> {
    let mut views = vec![
        "overview".into(),
        "execution-scenarios".into(),
        "security-gates".into(),
        "source-landmarks".into(),
        "synthesis".into(),
    ];
    if shapes
        .iter()
        .any(|shape| shape.contains("script") || shape.contains("npm"))
    {
        views.push("script-relations".into());
    }
    if shapes
        .iter()
        .any(|shape| shape.contains("github-actions") || shape.contains("container"))
    {
        views.push("coverage-unknowns".into());
    }
    views.sort();
    views.dedup();
    views
}

fn safe_embedded_json(value: &serde_json::Value) -> Result<String, ScvError> {
    let raw = serde_json::to_string(value)
        .map_err(|err| ScvError::Inspect(format!("visualization: JSON 직렬화 실패: {err}")))?;
    Ok(sanitize_html_payload(&raw)
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e"))
}

fn sanitize_html_payload(value: &str) -> String {
    value
        .replace("onerror=", "on-error=")
        .replace("onError=", "on-Error=")
        .replace("ONERROR=", "ON-ERROR=")
        .replace("javascript:", "javascript-redacted:")
        .replace("JavaScript:", "JavaScript-redacted:")
        .replace("JAVASCRIPT:", "JAVASCRIPT-redacted:")
}
