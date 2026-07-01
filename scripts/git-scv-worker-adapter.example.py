#!/usr/bin/env python3
"""Example Git-SCV worker adapter.

Copy this file outside the target repository and adjust the command/args for
your local LLM coding agent. Do not put OAuth tokens, API keys, or secrets in
this file or in environment variables consumed by Git-SCV.

Example use with the Codex backend:

  export GIT_SCV_CODEX_BIN=/path/to/git-scv-worker-adapter.py
  export GIT_SCV_CODEX_WORKER_ARGS="-"
  export GIT_SCV_AGENT_CMD=codex
  export GIT_SCV_AGENT_ARGS="exec --ephemeral --skip-git-repo-check --color never -"

Example Claude shape:

  export GIT_SCV_AGENT_CMD=claude
  export GIT_SCV_AGENT_ARGS="-p"
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys


def main() -> int:
    prompt = sys.stdin.read()
    command = os.environ.get("GIT_SCV_AGENT_CMD", "codex")
    args = os.environ.get(
        "GIT_SCV_AGENT_ARGS",
        "exec --ephemeral --skip-git-repo-check --color never -",
    )
    argv = [command, *shlex.split(args)]
    completed = subprocess.run(
        argv,
        input=prompt,
        text=True,
        capture_output=True,
        check=False,
    )
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
