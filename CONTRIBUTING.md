# Contributing to SecurePDF

Thank you for your interest in contributing! This guide covers everything you
need to develop, test, and submit changes.

## Development Environment

See [README.md — Development Setup](README.md#development-setup) for full
instructions. In short:

1. Install Go 1.24.0+ and `make`.
2. Create a Python virtual environment and install dev dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```
3. Build the Go engine: `make engine-clean-build`

## Running Tests

```bash
make all-tests          # All tests (Go + Python, unit + E2E)

# Scoped runs
make go-unit-tests      # Go unit tests (pkg/)
make go-e2e-tests       # Go E2E tests (cmd/)
make py-unit-tests      # Python unit tests
make py-e2e-tests       # Python E2E tests
make unit-tests         # Go + Python unit tests
make e2e-tests          # Go + Python E2E tests

# Quality
make lint               # go vet + ruff check
make fmt                # gofmt + ruff
make coverage           # Coverage summary for Go and Python
make bench              # Go benchmarks
```

## Branch & PR Conventions

- Use feature branches: `feature/short-description` (or `fix/...` for bug fixes).
- Keep PRs focused — one logical change per PR.
- Reference related issue numbers in the PR description.
- Ensure `make all-tests` and `make lint` pass before submitting.

## Adding a New Engine Feature (Pipeline Stage Checklist)

1. Add the stage function in `engine/pkg/pdf/`.
2. Register it in the pipeline sequence in `engine/pkg/pdf/pdf.go` (`Processor.Process`).
3. Add error/warning codes to `engine/pkg/receipt/codes.go` if needed
   (warnings W0xx are non-fatal; errors E0xx halt processing).
4. Write a `_test.go` file with > 80% coverage for the new stage.
5. Update `docs/engine-contract.md` with any new policy fields.
6. If the policy schema changed, update `engine/pkg/policy/policy.go` and the
   Python dataclasses in `python/securepdf/models/policy.py`.

## Release Process Summary

Tag `vX.Y.Z` on `master`; the release workflow (`.github/workflows/release.yml`)
automatically handles:

- Cross-compilation of engine binaries for all platforms
- Python wheel + sdist builds and PyPI upload
- Docker image build and push to ghcr.io
- GitHub Release creation with auto-generated notes
- Post-publish PyPI smoke test

## Pre-commit Hooks

Install hooks with `pre-commit install`. Active hooks:

- gofmt, go vet, Go unit tests
- black, pytest (non-e2e)
- trailing whitespace, YAML check, merge conflict check
