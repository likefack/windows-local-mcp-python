# CI validation

The repository-wide Windows validation baseline is the normal `Windows CI` workflow on `main`.

It runs the following independent gates on Windows with Python 3.12:

- `python -m ruff check .`
- `python -m compileall -q src tests`
- focused process-identity regressions
- focused race, recovery, and transaction regressions
- `python -m pytest`
- `git diff --check HEAD^ HEAD`

A final verification should be attributed to the exact `main` commit SHA that completed these gates; cancelled runs are not evidence of a passing gate.
