# SecurePDF

[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://github.com/ravishtiwari/pdf-secure/releases/tag/v0.0.1)
[![Go](https://img.shields.io/badge/Go-1.24.0-00ADD8.svg)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-141%20passing-success.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

SecurePDF is a lightweight, two-layer PDF security system that prioritizes **custodianship-by-access** over traditional DRM. Secure your PDFs with encryption, labels, provenance tracking, and tamper detection—all while maintaining forensic accountability.

**⚡ Status: v0.0.1 Released (Alpha)** — Production-ready core features with 141+ passing tests.

---

## 🛡️ Core Philosophy: Custodianship-by-Access

When a recipient opens a document secured by SecurePDF, they clearly understand:
- ✅ The document is intended specifically for them
- ✅ They are the designated custodian of this specific copy
- ✅ Sharing or misuse makes them directly responsible

SecurePDF focuses on **forensic accountability** and **clear intent** rather than impossible DRM or remote-kill switches.

---

## 🏗️ Architecture

SecurePDF uses a deliberate **two-layer design** for maximum performance and ease of integration:

- **🚀 Go Engine (`securepdf-engine`)**: High-performance, stateless transformation core
  - PDF parsing and rewriting
  - AES-256 encryption (PBKDF2 key derivation)
  - Labeling primitives (visible + invisible)
  - Provenance and tamper detection
  - Structured JSON receipts

- **🐍 Python SDK (`securepdf`)**: Developer-friendly orchestration layer
  - Policy composition and validation
  - Batch processing support
  - Type-safe API with beartype
  - Typed exceptions for all error codes
  - CLI wrapper included

```text
PDF + Policy → [ Go Engine ] → Secured PDF + Receipt (JSON)
```

---

## ✨ Key Features (v0.0.1)

### 🔐 Security
- **AES-256 Encryption** (default) with PBKDF2 key derivation
- **AES-128 & RC4-128** compatibility modes (with warnings)
- **Configurable Permissions**: Print, copy, modify controls
- **Weak Crypto Warnings**: Automatic alerts for legacy encryption

### 🏷️ Labels & Classification
- **Visible Labels**: Headers and footers with page filtering
- **Invisible Labels**: Metadata-based classification (no visual impact)

### 📊 Provenance & Tracking
- **Unique IDs**: Auto-generated document_id and copy_id (UUIDv4)
- **Timestamp Recording**: Track when PDFs were secured
- **Metadata Embedding**: All provenance data embedded in PDF

### 🛡️ Tamper Detection
- **SHA-256 Content Hashing**: Cryptographic hash of original content
- **Forensic Verification**: Detect if PDF has been modified
- **Multiple Hash Profiles**: Objects-only, content-streams, external

### 📋 Audit Trail
- **Structured Receipts**: JSON receipts for every transformation
- **Error Codes**: 13 error codes (E001-E012, E099)
- **Warning Codes**: 8 warning codes (W001-W008)
- **Comprehensive Metadata**: Hashes, IDs, timestamps, versions

---

## 🚀 Quick Start

### Installation

**Prerequisites:** Go 1.24.0+, Python 3.10+

```bash
# Clone repository
git clone https://github.com/ravishtiwari/pdf-secure.git
cd securepdf

# Build Go Engine
cd engine
go build -o ../bin/securepdf-engine ./cmd/securepdf-engine

# Install Python SDK
cd ../python
pip install -e .
```

### 5-Minute Tutorial

**1. Create a Policy (policy.json)**

```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "SecurePassword123!"
  },
  "provenance": {
    "enabled": true,
    "document_id": "auto",
    "copy_id": "auto"
  }
}
```

**2. Secure a PDF (Go Engine)**

```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json
```

**3. Or Use Python SDK**

```python
from securepdf import secure_pdf, Policy, EncryptionConfig, ProvenanceConfig

policy = Policy(
    encryption=EncryptionConfig(enabled=True, user_password="SecurePassword123!"),
    provenance=ProvenanceConfig(enabled=True, document_id="auto", copy_id="auto")
)

receipt = secure_pdf("input.pdf", "secured.pdf", policy)

if receipt.ok:
    print(f"✅ Success! Document ID: {receipt.document_id}")
else:
    print(f"❌ Failed: {receipt.error.message}")
```

**4. Batch Processing**

```python
from securepdf import batch_secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))

pairs = [
    ("doc1.pdf", "secured1.pdf"),
    ("doc2.pdf", "secured2.pdf"),
    ("doc3.pdf", "secured3.pdf"),
]

receipts = batch_secure_pdf(pairs, policy, max_workers=4)
print(f"✅ {sum(r.ok for r in receipts)} succeeded")
```

---

## 📚 Documentation

- **[Usage Guide](docs/usage.md)** - Comprehensive tutorial and API reference
- **[Architecture](docs/pdf-secure-architecture-final.md)** - System design and philosophy
- **[Engine Contract](docs/engine-contract.md)** - CLI interface and receipt schema
- **[CHANGELOG](CHANGELOG.md)** - Complete feature list and version history
- **[Release Notes](RELEASE_NOTES_v0.0.1.md)** - v0.0.1 highlights and known limitations

---

## 🧪 Testing

SecurePDF v0.0.1 ships with **141+ tests** covering all features:

```bash
# Run all tests
make all-tests

# Go tests only
make go-unit-tests go-e2e-tests

# Python tests only
make py-unit-tests py-e2e-tests
```

**Coverage:**
- ✅ All encryption modes (AES-256, AES-128, RC4-128)
- ✅ All labeling features (visible + invisible)
- ✅ Provenance tracking (auto + custom IDs)
- ✅ Tamper detection (all hash profiles)
- ✅ Error handling (all error codes)
- ✅ Batch processing
- ✅ CLI workflows

---

## 🛣️ Roadmap

### ✅ V1.0 (Released: v0.0.1)
- Encryption (AES-256/128, RC4-128)
- Labels (visible + invisible)
- Provenance tracking
- Tamper detection
- Structured receipts
- Python SDK with batch support

### 🔜 V1.1 (Q2 2026)
- Better error messages and validation UX
- UTF-8/internationalization for labels
- Policy validation dry-run mode
- Enhanced observability

### 🚀 V2.0 (Q3-Q4 2026)
- High-throughput worker mode
- Distributed architecture support
- Org policies and audit export
- Advanced labeling options
- PDF/UA accessibility support

---

## 📁 Project Structure

```
securepdf/
├── engine/           # Go transformation engine
│   ├── cmd/          # CLI entry point
│   ├── pkg/          # Core packages (policy, receipt, pdf)
│   └── testdata/     # Test fixtures
├── python/           # Python SDK
│   ├── securepdf/    # Package code
│   └── tests/        # Python tests
├── docs/             # Documentation
├── bin/              # Compiled binaries
└── scripts/          # Development tools
```

---

## 🤝 Contributing

We welcome contributions! Please:

1. Check existing issues or create a new one
2. Fork the repository
3. Create a feature branch
4. Add tests for new features
5. Ensure `make all-tests` passes
6. Submit a pull request

**Development workflow:**
```bash
# Run pre-commit hooks
pre-commit install

# Run tests
make all-tests

# Format code
make fmt

# Lint code
make lint
```

---

## 🐛 Bug Reports & Support

- **GitHub Issues**: https://github.com/ravishtiwari/pdf-secure/issues
- **Security Issues**: Please report via [GitHub Security Advisories](https://github.com/ravishtiwari/pdf-secure/security/advisories)
- **Documentation**: See `docs/` directory

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Implementation**: Ravish
- **AI Assistance**: Claude Sonnet 4.5 (Anthropic)
- **PDF Library**: [pdfcpu](https://github.com/pdfcpu/pdfcpu) (pure Go PDF library)
- **Type Checking**: [beartype](https://github.com/beartype/beartype) (Python runtime validation)

---

## ⚡ Quick Links

- 📖 [**Usage Guide**](docs/usage.md) - Get started in 10 minutes
- 🏗️ [**Architecture**](docs/pdf-secure-architecture-final.md) - Understand the design
- 📋 [**CHANGELOG**](CHANGELOG.md) - See what's new
- 🚀 [**Releases**](https://github.com/ravishtiwari/pdf-secure/releases) - Download binaries
- 💬 [**Discussions**](https://github.com/ravishtiwari/pdf-secure/discussions) - Ask questions

---

**SecurePDF v0.0.1** — Secure PDFs with custodianship, not DRM.

Built for accountability. Designed for developers. Ready for production.
