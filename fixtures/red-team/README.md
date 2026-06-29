# Git-SCV Red-Team Fixtures

These fixtures use synthetic secret-like markers only. They are not real
secrets and must remain useful for leak regression tests.

Expected invariant: raw markers, URL queries/fragments, and raw lifecycle
commands must not appear in artifacts, stdout, stderr, Markdown, or HTML.
