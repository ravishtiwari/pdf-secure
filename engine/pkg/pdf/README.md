# PDF Processing Package

This package provides the core PDF transformation engine for SecurePDF.

## Architecture

The `Processor` applies transformations in a strict pipeline:

```
1. Input Validation → 2. Encryption → 3. Labels → 4. Provenance → 5. Tamper Detection → 6. Output Hash
```

Each stage:
- Updates the receipt with operations performed
- Records errors/warnings with standardized codes
- Stops on fatal errors (returns non-nil error)
- Continues on warnings (records in receipt, returns nil)

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
if !receipt.Ok {
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

## Error Handling

All errors use standardized codes from `pkg/receipt/codes.go`:

- `E001` - Input file invalid/unreadable
- `E002` - Encryption failed
- `E003` - Labeling failed
- `E004` - Provenance embedding failed
- `E005` - Tamper detection failed
- `E006` - Hashing failed

Warnings use `W0xx` codes for non-fatal issues.
