# CLAUDE.md

## Project Overview

SecurePDF is a two-layer PDF security system: a stateless **Go engine** (core transforms) and a **Python SDK** (developer-friendly wrapper). Philosophy: "custodianship-by-access" — forensic accountability over DRM.

## Build & Test Commands

```bash
make engine-clean-build  # Build Go engine → bin/securepdf-engine
make all-tests           # All tests (Go + Python)

# Scoped test runs
make go-unit-tests      # Go unit tests (pkg/)
make go-e2e-tests       # Go E2E tests (cmd/)
make py-unit-tests      # Python unit tests
make py-e2e-tests       # Python E2E tests
make unit-tests         # Go + Python unit tests
make e2e-tests          # Go + Python E2E tests

make fmt                # gofmt + ruff
make lint               # go vet + ruff check
```

Single Go test: `cd engine && go test ./pkg/pdf/ -run TestName -v`
Single Python test: `cd python && pytest tests/test_sdk.py::test_name -v`

## Architecture

```
Python SDK (python/securepdf/sdk.py)
  → subprocess call →
Go Engine CLI (engine/cmd/securepdf-engine/main.go)
  → Pipeline (engine/pkg/pdf/pdf.go)
  → Output PDF + Receipt JSON
```

### Go Engine Pipeline (strict sequence in `pkg/pdf/pdf.go`)

1. Input validation → 2. Input hashing → 3. Working copy → 4. Visible labels → 5. Provenance embedding → 6. Tamper detection → 7. Encryption → 8. Output hashing

Each stage updates the receipt; warnings continue, errors halt.

### Key Modules

| Path | Role |
|------|------|
| `engine/cmd/securepdf-engine/main.go` | CLI entry point, arg parsing |
| `engine/pkg/pdf/pdf.go` | Pipeline orchestration (`Processor`) |
| `engine/pkg/pdf/encrypt.go` | AES-256/128, RC4-128, permissions |
| `engine/pkg/pdf/labels.go` | Visible watermark/footer/header |
| `engine/pkg/pdf/provenance.go` | document_id / copy_id embedding |
| `engine/pkg/pdf/tamper.go` | Content hash, tamper detection |
| `engine/pkg/policy/policy.go` | Policy schema, validation |
| `engine/pkg/receipt/codes.go` | Error (E0xx) / warning (W0xx) codes |
| `python/securepdf/sdk.py` | `secure_pdf()` — subprocess wrapper |
| `python/securepdf/models/policy.py` | Policy dataclasses |

### Error/Warning Code System

- **Warnings** (W001–W008): non-fatal, recorded in receipt, processing continues
- **Errors** (E001–E012, E099): fatal, processing halts
- **Exit codes**: 0=success, 2=policy invalid, 3=input invalid, 4=transform failed, 5=output failed, 6=runtime limit

### Crypto Profiles

- `strong` (default): AES-256
- `compat`: AES-128
- `legacy`: RC4-128 (deprecated, emits W001)
- `auto`: maps to strong

### Engine Runtime Options (`--engine-opt key=value`)

`reject_weak_crypto` (bool), `timeout_ms` (int, default 60000), `max_input_mb` (int, default 200), `max_memory_mb` (int, default 512)

## Dependencies

- **Go 1.24.0** with **pdfcpu v0.11.1** (pure Go PDF library)
- **Python**: `beartype` (runtime type checking), `pypdf` + `cryptography` (dev/test)

## Pre-commit Hooks

gofmt, go vet, Go unit tests, black, pytest (non-e2e), trailing whitespace, YAML check, merge conflict check.

## Contract Reference

Engine CLI contract and schemas: `docs/engine-contract.md`.
