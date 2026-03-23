# SecurePDF v0.0.1 Release Notes

**Release Date:** February 27, 2026
**Status:** Initial Public Release (Alpha)

---

## 🎉 Introducing SecurePDF

SecurePDF is a lightweight, two-layer PDF security system that prioritizes **custodianship-by-access** over traditional DRM. When a recipient opens a secured PDF, they understand their responsibility as the custodian of that specific copy—making security about accountability rather than impossible restrictions.

This is the **first public release** of SecurePDF, providing production-ready tools for securing PDFs with encryption, labels, provenance tracking, and tamper detection.

---

## 🌟 What is SecurePDF?

SecurePDF transforms PDFs according to explicit security policies, embedding:
- **Strong encryption** (AES-256 by default)
- **Visible and invisible labels** for classification
- **Provenance tracking** (unique document and copy IDs)
- **Tamper detection hashes** for forensic verification

The system produces a **structured receipt** for every transformation, creating an audit trail for compliance and accountability.

### Architecture

SecurePDF uses a clean two-layer design:

- **🚀 Go Engine (`securepdf-engine`)**: A high-performance, stateless transformation core that handles PDF internals, encryption, and security primitives
- **🐍 Python SDK (`securepdf`)**: A developer-friendly wrapper for policy composition, orchestration, and integration

```text
PDF + Policy → [ Go Engine ] → Secured PDF + Receipt (JSON)
```

---

## ✨ Key Features (v0.0.1)

### 🔐 Encryption & Security

- **AES-256 Encryption** (default): Industry-standard strong encryption
- **AES-128 Compatibility Mode**: For broader viewer support
- **RC4-128 (deprecated)**: Retained for legacy interoperability only; RC4 is a broken cipher and must not be used to protect confidential documents — emits W001 warning on use
- **PBKDF2 Key Derivation**: Secure password-based encryption
- **Configurable Permissions**: Control print, copy, and modify access
- **Weak Crypto Warnings**: Automatic alerts when using legacy encryption
- **Optional Rejection**: Block weak crypto profiles if required

### 🏷️ Labels & Classification

- **Visible Labels**: Add headers or footers to PDFs
  - Page filtering (all pages, first page, or custom ranges)
  - Configurable placement and text
- **Invisible Labels**: Embed metadata-based labels
  - Custom namespace support
  - No visual impact on PDF appearance

### 📊 Provenance & Tracking

- **Automatic ID Generation**: Unique document_id and copy_id (UUIDv4)
- **Custom ID Support**: Use your own identifiers if needed
- **Timestamp Recording**: Track when PDFs were secured
- **Version Tracking**: Record engine and policy versions
- **Metadata Embedding**: All provenance data embedded in PDF

### 🛡️ Tamper Detection

- **Content Hashing**: SHA-256 hash of original PDF content
- **Metadata Embedding**: Hash stored in PDF for verification
- **Multiple Hash Profiles**:
  - `objects_only` (recommended): Hash PDF objects
  - `content_streams`: Hash content streams
  - `external`: Hash using external tools
- **Forensic Verification**: Detect if PDF has been modified

### 📋 Structured Receipts

Every transformation produces a JSON receipt containing:
- Success/failure status
- Input and output hashes (SHA-256)
- Document and copy IDs
- Warnings (non-fatal issues)
- Errors (fatal failures with codes)
- Timestamps and version information

### 🚨 Error & Warning System

- **13 Error Codes** (E001-E012, E099): Fatal failures with detailed messages
- **8 Warning Codes** (W001-W008): Non-fatal issues that don't stop processing
- **Typed Exceptions** (Python SDK): Specific exception classes for each error code

---

## 🚀 Quick Start

### Installation

**Prerequisites:**
- Go 1.24.0+ (for engine)
- Python 3.10+ (for SDK)

**Build the Go Engine:**
```bash
cd engine
go build -o ../bin/securepdf-engine ./cmd/securepdf-engine
```

**Install Python SDK:**
```bash
cd python
pip install -e .
```

### Usage

#### Go Engine (CLI)

```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json \
  --engine-opt reject_weak_crypto=true \
  --engine-opt timeout_ms=30000
```

**Sample Policy (policy.json):**
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "SecurePass123!",
    "crypto_profile": "strong"
  },
  "labels": {
    "mode": "visible",
    "visible": {
      "text": "CONFIDENTIAL - Internal Use Only",
      "placement": "footer",
      "pages": "all"
    }
  },
  "provenance": {
    "enabled": true,
    "document_id": "auto",
    "copy_id": "auto"
  },
  "tamper_detection": {
    "enabled": true,
    "hash_alg": "sha256"
  }
}
```

#### Python SDK

**Simple Example (5 lines):**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))
receipt = secure_pdf("input.pdf", "output.pdf", policy)
print(f"Success: {receipt.ok}, Document ID: {receipt.document_id}")
```

**Full-Featured Example:**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig, LabelsConfig, \
    VisibleLabel, ProvenanceConfig, TamperDetectionConfig

# Create comprehensive policy
policy = Policy(
    encryption=EncryptionConfig(
        enabled=True,
        mode="password",
        user_password="StrongPassword123!",
        crypto_profile="strong",
        allow_print=True,
        allow_copy=False,
        allow_modify=False
    ),
    labels=LabelsConfig(
        mode="visible",
        visible=VisibleLabel(
            text="CONFIDENTIAL",
            placement="footer",
            pages="all"
        )
    ),
    provenance=ProvenanceConfig(
        enabled=True,
        document_id="auto",
        copy_id="auto"
    ),
    tamper_detection=TamperDetectionConfig(
        enabled=True,
        hash_alg="sha256"
    )
)

# Secure the PDF
receipt = secure_pdf("document.pdf", "secured-document.pdf", policy)

# Check results
if receipt.ok:
    print(f"✅ Success!")
    print(f"   Document ID: {receipt.document_id}")
    print(f"   Copy ID: {receipt.copy_id}")
    print(f"   Output Hash: {receipt.output_sha256}")

    if receipt.warnings:
        print(f"⚠️  Warnings: {len(receipt.warnings)}")
        for w in receipt.warnings:
            print(f"   [{w.code}] {w.message}")
else:
    print(f"❌ Failed: {receipt.error.message}")
```

**Batch Processing:**
```python
from securepdf import batch_secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))

# Process multiple PDFs in parallel
pairs = [
    ("doc1.pdf", "secured1.pdf"),
    ("doc2.pdf", "secured2.pdf"),
    ("doc3.pdf", "secured3.pdf"),
]

receipts = batch_secure_pdf(pairs, policy, max_workers=4)

for i, receipt in enumerate(receipts):
    print(f"PDF {i+1}: {'✅ Success' if receipt.ok else '❌ Failed'}")
```

**CLI Wrapper:**
```bash
python -m securepdf secure \
  --in document.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json \
  --engine-opt reject_weak_crypto=true
```

---

## 📚 What's Included

### Go Engine Features
✅ One-shot stateless CLI
✅ Policy-driven transformation
✅ AES-256/128, RC4-128 encryption
✅ Visible & invisible labels
✅ Provenance embedding
✅ Tamper detection
✅ Structured JSON receipts
✅ Runtime limits (timeout, memory, file size)
✅ Comprehensive error handling
✅ 80+ unit and E2E tests

### Python SDK Features
✅ High-level `secure_pdf()` API
✅ Batch processing with `batch_secure_pdf()`
✅ Type-safe policy dataclasses
✅ Typed exception hierarchy
✅ CLI wrapper (`python -m securepdf`)
✅ Engine options support
✅ 39 unit and E2E tests

### Documentation
✅ Architecture document
✅ Engine contract specification
✅ API documentation
✅ CHANGELOG
✅ Usage examples

---

## ⚠️ What's NOT Included (v0.0.1)

SecurePDF focuses on **custodianship and accountability**, not impossible DRM. Here's what v0.0.1 does NOT provide:

❌ **Remote Revocation**: Once distributed, PDFs cannot be remotely disabled
❌ **Identity Binding**: No built-in recipient identity verification (OSS)
❌ **DRM/Rights Management**: No prevention of screenshots or camera capture
❌ **Guaranteed Acknowledgment Display**: Viewer-dependent feature support
❌ **Post-Distribution Control**: No "phone home" or tracking after distribution
❌ **Digital Signatures**: Not a signing/verification system
❌ **Heavy Observability**: No built-in metrics or tracing (structured logs only)

These are **intentional design decisions** aligned with our custodianship-by-access philosophy.

---

## 🔒 Security Guarantees

### What We Guarantee (v0.0.1)

✅ **Strong Encryption**: AES-256 by default
✅ **Secure Key Derivation**: PBKDF2 with high iteration count
✅ **Tamper Detection**: Original content hash embedded
✅ **Provenance Tracking**: Unique identifiers per copy
✅ **Audit Trail**: Structured receipts for compliance
✅ **No Silent Weakening**: Weak crypto always produces warnings
✅ **Stateless Engine**: No external dependencies or network calls

### What We Don't Guarantee

⚠️ **Screen Capture Prevention**: Impossible to prevent screenshots
⚠️ **Viewer Consistency**: Acknowledgment display varies by PDF viewer
⚠️ **Post-Distribution Tracking**: No "phone home" capability
⚠️ **Perfect Memory Limits**: Best-effort (GC-dependent)

---

## 🧪 Testing & Quality

SecurePDF v0.0.1 ships with comprehensive test coverage:

- **141+ Total Tests**
  - 102 Go tests (unit + E2E + golden)
  - 39 Python tests (unit + E2E)
- **All Core Features Tested**
  - Encryption (all profiles)
  - Labels (visible + invisible)
  - Provenance (auto + custom IDs)
  - Tamper detection (all hash profiles)
  - Error handling (all error codes)
  - Batch processing
- **Pre-commit Hooks**: gofmt, go vet, pytest, linting
- **Continuous Testing**: Makefile targets for all test suites

---

## 🛣️ Known Limitations

### Technical Limitations

1. **Viewer-Dependent Acknowledgment**: The custodianship acknowledgment message may not display in all PDF viewers. This is a PDF standard limitation, not a SecurePDF bug.

2. **Memory Check Best-Effort**: The `max_memory_mb` runtime limit depends on Go's garbage collector and may not catch all memory overruns.

3. **Timeout Granularity**: Timeouts are checked between pipeline stages, not during long-running operations. A complex PDF stage may complete before timeout is checked.

4. **PDF/UA Support**: Accessibility tagging for labels is not included in v0.0.1.

### Architectural Limitations

1. **No Revocation**: Once a PDF is distributed, it cannot be remotely disabled or updated.

2. **No Identity Binding**: OSS v0.0.1 does not bind PDFs to verified recipient identities.

3. **No Server Component**: v0.0.1 is purely local transformation—no centralized control.

---

## 🚦 Roadmap: What's Next

### V1.1 (Planned: Q2 2026)

- Better error messages and policy validation UX
- UTF-8 and internationalization support for labels
- Lightweight batch processing improvements in Python
- Additional runtime guardrails and safety checks
- Policy validation dry-run mode
- Enhanced observability options

### V2.0 (Planned: Q3-Q4 2026)

- High-throughput worker mode for Go engine
- Optional distributed architecture support
- Paid-tier features: org policies, audit export, FastAPI service
- Advanced labeling and watermarking options
- PDF/UA accessibility support

---

## 📖 Documentation

- **Architecture**: `docs/pdf-secure-architecture-final.md`
- **Engine Contract**: `docs/engine-contract.md`
- **CHANGELOG**: `CHANGELOG.md`
- **Quick Start**: `README.md`
- **API Reference**: Inline docstrings (Go godoc, Python docstrings)

---

## 🙏 Acknowledgments

SecurePDF v0.0.1 was developed with:
- **Implementation**: Ravish
- **AI Assistance**: Claude Sonnet 4.5 (Anthropic)
- **Testing**: Comprehensive test suite (141+ tests)
- **Dependencies**: pdfcpu (PDF library), beartype (Python runtime checking)

---

## 🐛 Bug Reports & Feedback

We welcome feedback and bug reports!

- **GitHub Issues**: https://github.com/ravishtiwari/pdf-secure/issues
- **Security Issues**: Please report via [GitHub Security Advisories](https://github.com/ravishtiwari/pdf-secure/security/advisories)

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🎯 Get Started

Ready to secure your PDFs? Check out:

1. **README.md** - Installation and quick start
2. **docs/usage.md** - Comprehensive usage guide (coming soon)
3. **CHANGELOG.md** - Complete feature list
4. **examples/** - Sample policies and scripts

---

**SecurePDF v0.0.1** - Secure PDFs with custodianship, not DRM.

Built for accountability, designed for developers, ready for production.
