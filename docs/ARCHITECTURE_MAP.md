# Architecture Map

`architecture_map.json` summarizes repository shape and major sectors for
human navigation and agent orchestration.

It records:

- Detected repo shapes such as npm package, Rust project, workflow-heavy repo,
  containerized app, script collection, or unknown/mixed.
- Sector names, representative paths, primary role, model-input status, and
  gate status.
- Entrypoints such as package scripts, build scripts, hooks, workflow steps, or
  binary/config surfaces.
- A human architecture summary with `safe_claim_made:false`.
- Recommended visualization views for the detected shape.

The map is derived from already-generated static artifacts. It does not read
new target files and does not execute target content.

Limitations and unsupported surfaces must stay visible. If a surface is only
name-detected or parse-failed, the architecture map may guide review order, but
it cannot support a safe/install/run claim.
