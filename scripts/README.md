# SecurePDF Test CLI

Unified test tool combining encryption, provenance, and foundation verification.

## Usage

```bash
./scripts/test [COMMAND] [OPTIONS]
```

## Commands

### 1. `encryption` - Test PDF Encryption

Test PDF encryption using the SecurePDF Go engine.

**Example:**
```bash
./scripts/test encryption \
  --in test-pdfs/sample-input.pdf \
  --out output.pdf \
  --policy testdata/policies/valid/01-minimal-encryption-only.json
```

**Options:**
- `--in, -i`: Input PDF file (required)
- `--out, -o`: Output PDF file (required)
- `--policy, -p`: Policy JSON file (required)
- `--engine-bin, -b`: Path to securepdf-engine binary (default: `bin/securepdf-engine`)
- `--engine-opt, -e`: Engine runtime options as `key=value` (can be repeated)

**Engine Options:**
- `reject_weak_crypto=true|false`
- `timeout_ms=60000`
- `max_input_mb=200`
- `max_memory_mb=512`

---

### 2. `provenance` - Test Provenance Tracking

Test document and copy ID generation and embedding.

**Example:**
```bash
./scripts/test provenance \
  --in test-pdfs/sample-input.pdf \
  --out output.pdf \
  --verify-metadata
```

**Options:**
- `--in, -i`: Input PDF file (required)
- `--out, -o`: Output PDF file (required)
- `--engine-bin, -b`: Path to securepdf-engine binary
- `--password`: Encrypt output with this password
- `--input-password`: Password for encrypted input PDFs
- `--document-id`: Document ID (default: `auto`)
- `--copy-id`: Copy ID (default: `auto`)
- `--verify-metadata`: Verify provenance in PDF metadata (requires pypdf)
- `--validate-only`: Skip processing, only validate existing metadata

---

### 3. `verify-foundation` - Verify Foundation Setup

Verify that the SecurePDF foundation is properly set up.

**Example:**
```bash
./scripts/test verify-foundation
```

Checks for:
- Repository layout (engine/, python/, docs/)
- Engine module (go.mod)
- CLI skeleton
- Documentation files
- Policy loader
- Receipt writer
- Python package skeleton

---

## Migration from Old Scripts

| Old Command | New Command |
|-------------|-------------|
| `python scripts/test_encryption.py secure ...` | `./scripts/test encryption ...` |
| `python scripts/test_provenance.py ...` | `./scripts/test provenance ...` |
| `python scripts/verify_foundation.py` | `./scripts/test verify-foundation` |

---

## Requirements

- Python virtual environment at `.venv/`
- `typer` and `rich` packages installed
- For provenance metadata verification: `pypdf` package (optional)

---

## Implementation Details

The unified CLI is implemented using [Typer](https://typer.tiangolo.com/) with three subcommands:
- Each original script becomes a Typer command
- Shared utilities are defined once
- Rich console output for better UX
- Automatic help generation
