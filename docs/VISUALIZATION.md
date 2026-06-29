# Git-SCV Visualization

`architecture.html` is a default human-facing RC artifact. It helps users
understand an unfamiliar repository before install, build, test, run, model
input approval, or sensitive raw review.

## Purpose

- Show the repository shape and main sectors.
- Show user-action reachability for install/build/test/run/open editor/hook
  scenarios.
- Show script, manifest, hook, workflow, config, dependency, sensitive, and
  gate relationships.
- Show required approvals and blocked actions.
- Show coverage limits, unsupported surfaces, unresolved relations, and
  follow-up requirements.
- Reflect cross-unit synthesis and whole-repo diagnosis.

`architecture.html` is not an execution approval and does not claim safety.

## Default Views

- Overview Map.
- Execution Scenario Reachability.
- Script Relationship View.
- Security Gate Overlay.
- Coverage / Unknowns.
- Source Landmarks.
- Synthesis View.

The machine-readable inputs are `architecture_map.json`, `relation_map.json`,
`source_landmarks.json`, `visualization_index.json`,
`reachability_scenarios.json`, `connection_graph.json`, `gates.json`,
`supported_surfaces.json`, `review.json`, and `synthesis.json`.

## Security Contract

- No external CDN or network fetch.
- No target repository JavaScript or HTML execution.
- No `eval` or `new Function`.
- No inline event handlers from target data.
- All target-derived labels and details are escaped or embedded as sanitized
  JSON data.
- Raw sensitive content is not included.
- Raw lifecycle commands are not included.
- URL query, fragment, and userinfo are redacted before visualization.
- The viewer follows the selected path privacy policy.
- `architecture.html` participates in artifact leak validation and the artifact
  manifest hash chain.

## Truncation

The default viewer is `basic`. It prefers summary clusters over very large
graphs. If graph limits are exceeded, `visualization_index.json` records
`truncated:true` with node and edge limits. Truncation is a coverage limitation
and must be reflected in brief/report/synthesis before any no-blocker wording.

## User Guidance

Read in this order:

1. `brief.md`.
2. `architecture.html` Overview Map.
3. Execution Scenario Reachability.
4. Security Gate Overlay.
5. Coverage / Unknowns.
6. Source Landmarks.
7. Synthesis View.

Before any execution approval, run:

```sh
git-scv case verify-source <case-id>
git-scv case next-action <case-id> --action install --argv <program> <arg>
```
