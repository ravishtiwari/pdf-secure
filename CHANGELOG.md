# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1] - 2026-02-27

### Added

#### Core Features
- **PDF Encryption**: AES-256 (strong), AES-128 (compat), and RC4-128 (legacy) encryption support
- **Password Protection**: PBKDF2 key derivation with configurable iteration counts
- **Crypto Profiles**: `strong` (AES-256, default), `compat` (AES-128), `legacy` (RC4-128), `auto` (maps to strong)
- **PDF Permissions**: Configurable print, copy, and modify permissions for encrypted PDFs
- **Visible Labels**: Header and footer overlays with page filtering (all/first/range)
- **Invisible Labels**: Metadata-based labeling with custom namespace support
- **Provenance Tracking**: Automatic generation and embedding of document_id and copy_id (UUIDv4 format)
- **Tamper Detection**: SHA-256 content hash computation and embedding in PDF metadata
- **Hash Profiles**: `objects_only` (recommended), `content_streams`, and `external` profiles
- **Custodianship Acknowledgment**: Fixed default acknowledgment text embedded in PDFs (OSS v0.0.1)
- **Structured Receipts**: JSON receipts with transformation audit trail, hashes, warnings, and errors

#### Go Engine (`securepdf-engine`)
- **One-Shot CLI**: Stateless PDF transformation with policy-driven security
- **Policy Schema**: JSON-based policy definition with validation (version 1.0)
- **Receipt Generation**: Structured JSON receipts with stable schema
- **Runtime Options**: Configurable timeout, input size limit, and memory limit
- **Input Validation**: PDF format validation and file size checks
- **Working File Management**: Safe temporary file handling during transformation
- **Pipeline Architecture**: Sequential stages (validate → hash → copy → label → provenance → tamper → encrypt → output)
- **Error Handling**: Comprehensive error codes (E001-E012) with detailed messages
- **Warning System**: Non-fatal warnings (W001-W008) for policy and processing issues

#### Python SDK (`securepdf`)
- **`secure_pdf()` Function**: High-level API for securing single PDFs
- **`batch_secure_pdf()` Function**: Parallel processing of multiple PDFs with order preservation
- **Policy Dataclasses**: Type-safe policy construction with validation
- **Receipt Parsing**: Structured receipt objects with typed fields
- **Typed Exceptions**: Specific exception classes for each error code (E001-E012)
- **CLI Wrapper**: `python -m securepdf` command-line interface
- **Engine Options Support**: Pass runtime options to Go engine
- **Beartype Runtime Checking**: Type safety at runtime

#### Documentation
- **Architecture Document**: Complete system design and responsibility matrix
- **Engine Contract**: Detailed CLI interface and receipt schema specification
- **Project Plans**: 14-day development roadmap and milestones
- **CLAUDE.md**: Project instructions for AI assistants
- **Code Review Guidelines**: Review criteria and standards

#### Testing
- **Go Unit Tests**: 50+ unit tests for policy, receipt, encryption, labels, provenance, and tamper detection
- **Go E2E Tests**: 30+ end-to-end tests covering full pipeline scenarios
- **Python Unit Tests**: 39 tests for SDK, models, and exceptions
- **Python E2E Tests**: CLI, batch processing, and exception handling tests
- **Golden Tests**: Receipt output verification tests
- **Fixture-Based Testing**: Valid and invalid policy test fixtures

#### Error Codes (E001-E012)
- **E001**: Policy invalid or malformed
- **E002**: Input PDF invalid or corrupted
- **E003**: Input PDF uses unsupported features (or weak crypto rejected)
- **E004**: PDF encryption failed
- **E005**: Label application failed
- **E006**: Provenance embedding failed
- **E007**: Tamper detection hash computation failed
- **E008**: Output file cannot be written
- **E009**: Processing timeout exceeded
- **E010**: Memory limit exceeded
- **E011**: Input file cannot be read
- **E012**: Weak crypto rejected by policy
- **E099**: Internal error (unexpected)

#### Warning Codes (W001-W008)
- **W001**: Weak crypto profile requested (RC4-128)
- **W002**: Weak crypto rejected (when reject_weak_crypto=true)
- **W003**: Viewer-dependent acknowledgment (may not display in all viewers)
- **W004**: Unsupported PDF feature detected (processing continues)
- **W005**: Label partially applied (some pages may not have labels)
- **W006**: Provenance partially applied (some metadata may be missing)
- **W007**: Tamper hash embed failed (hash computed but not embedded)
- **W008**: Unknown policy field detected (field ignored)

#### Engine Runtime Options
- **`reject_weak_crypto`**: Reject weak crypto profiles (true/false, default: false)
- **`timeout_ms`**: Processing timeout in milliseconds (default: 60000)
- **`max_input_mb`**: Maximum input file size in MB (default: 200)
- **`max_memory_mb`**: Maximum memory usage in MB (default: 512)

#### Developer Tools
- **Pre-commit Hooks**: gofmt, go vet, black, pytest, trailing whitespace, YAML check
- **Makefile**: Build, test, and lint automation
- **Test CLI**: Unified test tool (`scripts/test.py`) for encryption, provenance, and foundation verification
- **Modular Test CLI**: New refactored test CLI (`scripts/test_new.py`) with lazy loading

### Changed
- **Default Crypto Profile**: Set to `strong` (AES-256) for maximum security
- **Policy Version**: Using version 1.0 schema
- **Receipt Schema**: Finalized V1 receipt format with all required fields

### Fixed
- **Working File Cleanup**: Proper temporary file cleanup after processing
- **Receipt Writing**: Receipts always written even on failure
- **Error Propagation**: Consistent error handling throughout pipeline
- **Hash Computation**: Accurate content hash calculation for tamper detection
- **Memory Management**: Best-effort memory limit checking
- **Timeout Handling**: Graceful timeout detection between pipeline stages

### Security
- **Strong Crypto Defaults**: AES-256 encryption enabled by default
- **Weak Crypto Warnings**: RC4-128 usage emits warnings (W001)
- **Optional Rejection**: Weak crypto can be rejected via engine option
- **Tamper Detection**: Original content hash embedded for forensic verification
- **Password Key Derivation**: PBKDF2 with high iteration count
- **Secure File Permissions**: Temporary policy and receipt files use 0600 permissions

### Known Limitations
- **Viewer-Dependent Acknowledgment**: Acknowledgment display depends on PDF viewer support
- **No Revocation**: Once distributed, PDFs cannot be remotely revoked or disabled
- **No Identity Binding**: OSS v0.0.1 does not bind PDFs to verified recipient identities
- **Memory Check Best-Effort**: Memory limit checking depends on Go garbage collector
- **Timeout Granularity**: Timeouts checked between stages, not during long-running operations
- **PDF/UA Support**: Accessibility tagging for labels not included in v0.0.1

### Technical Details
- **Go Version**: 1.24.0
- **pdfcpu Version**: 0.11.1 (pure Go PDF library)
- **Python Version**: 3.10+ (type hints, beartype)
- **Dependencies**: Minimal - Go standard library + pdfcpu, Python beartype + standard library

### Performance
- **Stateless Engine**: No external state, network calls, or storage dependencies
- **Streaming I/O**: Memory-efficient PDF processing
- **Bounded Memory**: Configurable memory limits with best-effort enforcement
- **Parallel Batch Processing**: Python SDK supports concurrent PDF processing

### Contributors
- Ravish (Implementation)
- Claude Sonnet 4.5 (Code assistance and review)

---

## Release Notes

SecurePDF v0.0.1 is the initial release of a lightweight PDF security system focused on **custodianship-by-access** rather than DRM. The system provides encryption, labeling, provenance tracking, and tamper detection with a clean two-layer architecture:

- **Go Engine**: High-performance, stateless PDF transformation core
- **Python SDK**: Developer-friendly wrapper with batch processing support

This release includes all planned V1.0 features with comprehensive test coverage (141+ tests) and production-ready code quality.

### Quick Start

**Go Engine:**
```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json
```

**Python SDK:**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))
receipt = secure_pdf("input.pdf", "output.pdf", policy)
print(f"Success: {receipt.ok}, Document ID: {receipt.document_id}")
```

### What's Next (V1.1 Roadmap)

- Better error messages and policy validation UX
- UTF-8 and internationalization support for labels
- Lightweight batch processing improvements
- Additional runtime guardrails
- Policy validation dry-run mode
- Enhanced observability

---

[0.0.1]: https://github.com/ravishtiwari/pdf-secure/releases/tag/v0.0.1
