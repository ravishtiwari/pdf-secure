# PDF Processing Package

This package provides the core PDF transformation engine for SecurePDF.

## Architecture

The `Processor` applies transformations in a strict pipeline:

```
1. Input Validation → 2. Input Hashing → 3. Input Copy → 4. Labels → 5. Provenance → 6. Tamper Detection → 7. Encryption (or Copy) → 8. Output Hashing
```

Each stage:
- Updates the receipt with operations performed
- Records errors/warnings with standardized codes
- Stops on fatal errors (returns non-nil error)
- Continues on warnings (records in receipt, returns nil)

**Note:** A working copy is created early in the pipeline; if encryption is disabled, that working file is copied to the output path in Stage 7.

## Modules

- **pdf.go** - Main processor and pipeline orchestration
- **encrypt.go** - PDF encryption with AES-256/128, RC4-128
- **labels.go** - Visible watermark/label overlay
- **provenance.go** - Document ID and copy ID embedding
- **tamper.go** - Content hash and tamper detection
- **hash.go** - SHA-256 hashing utilities

## Usage

```go
import (
    "securepdf-engine/pkg/pdf"
    "securepdf-engine/pkg/policy"
)

// Load policy
pol, _ := policy.LoadFromFile("policy.json")

// Create processor
proc := pdf.NewProcessor(pol, "input.pdf", "output.pdf")

// Process PDF
receipt, err := proc.Process()
if err != nil {
    log.Fatalf("Processing failed: %v", err)
}

// Check receipt
if !receipt.OK {
    log.Printf("Processing completed with errors: %d", len(receipt.Errors))
}
```

## Dependencies

- **pdfcpu** (github.com/pdfcpu/pdfcpu) - PDF manipulation library
- Apache-2.0 license, pure Go, supports AES-256 encryption

## Testing

```bash
# Unit tests
go test ./pkg/pdf

# E2E tests (with real PDFs)
go test ./cmd/securepdf-engine -tags=e2e
```

## Crypto Profiles

The engine supports the following encryption profiles:
- **strong** (default): AES-256 encryption (recommended).
- **compat**: AES-128 encryption (for older viewers).
- **legacy**: RC4-128 encryption (deprecated, emits warning).
- **auto**: Selects the best available profile (defaults to **strong**).
## Error Handling

All errors use standardized codes from `pkg/receipt/codes.go`:

- `E001` - Policy invalid
- `E002` - Input file invalid/unreadable
- `E003` - Input PDF unsupported
- `E004` - Encryption failed
- `E005` - Labeling failed
- `E006` - Provenance embedding failed
- `E007` - Tamper detection failed
- `E008` - Output write/hashing failed

Warnings use `W0xx` codes for non-fatal issues (e.g., `W001` for weak crypto).
