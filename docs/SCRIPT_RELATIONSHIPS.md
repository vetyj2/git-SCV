# Script Relationships

`relation_map.json` records how scenarios, scripts, manifests, hooks,
workflows, config files, sensitive candidates, and gates relate within the
observed scope.

Relation kinds include:

- `install-lifecycle`
- `build-lifecycle`
- `hook-lifecycle`
- `reachable-under-scenario`
- `requires-user-approval`
- `excludes-from-model-input`
- `gates`
- `depends-on`
- `configures`
- `unknown`

Every relation has an id, source, target, kind, confidence, evidence references
when available, blocked gates, and unresolved status.

The relation map intentionally stores sanitized node ids and relation labels
instead of raw command bodies. If a command target cannot be resolved without
reading gated raw content, the relation remains unresolved and synthesis must
surface a follow-up task rather than claiming safety.
