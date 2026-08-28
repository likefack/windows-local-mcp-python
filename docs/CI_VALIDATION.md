# CI validation

The repository-wide Windows validation baseline is the normal `Windows CI` workflow on `main`.

It runs the following independent gates on Windows:

- Python 3.12 `python -m ruff check .`
- Python 3.12 `python -m compileall -q src tests`
- PowerShell parser validation for the production install/recovery/verification scripts
- Python 3.12 pytest shard-completeness validation
- Python 3.12 core pytest for every normally collected test except `tests/test_runtime_closure_integration.py`
- Python 3.12 runtime-closure pytest for `tests/test_runtime_closure_integration.py` on an independent Windows runner
- Python 3.13 wheel-shaped package installation plus real MCP stdio negotiation
- `git diff --check HEAD^ HEAD`

The pytest coverage invariant is mechanical rather than a manually maintained test manifest. `tests/ci_shards.py` collects the complete pytest node-id set, the core shard, and the runtime-closure shard, then fails CI unless the two shards are disjoint and their union exactly equals the complete collection. New tests therefore enter the core shard automatically unless they are added to the explicitly isolated runtime-closure file.

The runtime-closure test is split out only for CI scheduling. It still remains part of the repository-wide pytest coverage and continues to exercise creation of an external isolated runtime and rejection of mutable-checkout / `.dev-tmp` contamination. The split must not be interpreted as reducing the security contract or as replacing Windows live verification required by the Approved Host or Sandbox boundaries.

The former sequential focused pytest groups are intentionally not rerun before the repository pytest shards. Their tests remain in the complete collection, so removing those duplicate invocations changes scheduling only and does not remove regression coverage.

A final verification should be attributed to the exact `main` commit SHA that completed these gates; cancelled runs are not evidence of a passing gate.
