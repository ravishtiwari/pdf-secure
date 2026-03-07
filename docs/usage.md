# SecurePDF Usage Guide

A comprehensive guide to using SecurePDF for securing PDF documents with encryption, labels, provenance tracking, and tamper detection.

**Version:** 0.0.1
**Last Updated:** February 27, 2026

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Policy Schema](#policy-schema)
4. [Go Engine CLI](#go-engine-cli)
5. [Python SDK](#python-sdk)
6. [Common Use Cases](#common-use-cases)
7. [Receipt Structure](#receipt-structure)
8. [Error Handling](#error-handling)
9. [Engine Options](#engine-options)
10. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **Go 1.24.0+** (for building the engine)
- **Python 3.10+** (for using the SDK)

### Building the Go Engine

```bash
# Clone the repository
git clone https://github.com/ravishtiwari/pdf-secure.git
cd pdf-secure

# Build the engine
cd engine
go build -o ../bin/securepdf-engine ./cmd/securepdf-engine

# Verify installation
../bin/securepdf-engine --help
```

### Installing the Python SDK

```bash
# From the repository root
cd python
pip install -e .

# Verify installation
python -m securepdf --version
```

### System Requirements

- **Disk Space**: ~50MB for binaries and dependencies
- **Memory**: 512MB minimum (configurable via `max_memory_mb`)
- **OS**: Linux, macOS, Windows (Go cross-compilation supported)

---

## Quick Start

### 5-Minute Tutorial

**Step 1: Create a Policy File**

Create `policy.json`:
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "SecurePassword123!"
  }
}
```

**Step 2: Secure a PDF (Go Engine)**

```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json
```

**Step 3: Check the Receipt**

```bash
cat receipt.json | jq '.ok, .document_id'
```

**Step 4: Use Python SDK**

```python
from securepdf import secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="SecurePassword123!"))
receipt = secure_pdf("input.pdf", "secured.pdf", policy)

print(f"Success: {receipt.ok}")
print(f"Document ID: {receipt.document_id}")
```

---

## Policy Schema

The policy defines all security settings for PDF transformation.

### Policy Structure

```json
{
  "policy_version": "1.0",
  "encryption": { ... },
  "labels": { ... },
  "provenance": { ... },
  "tamper_detection": { ... },
  "ack": { ... }
}
```

### Encryption Configuration

```json
{
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "user-secret",
    "owner_password": "admin-secret",
    "crypto_profile": "strong",
    "allow_print": true,
    "allow_copy": false,
    "allow_modify": false
  }
}
```

**Fields:**
- `enabled` (bool, required): Enable/disable encryption
- `mode` (string): `"password"` (only supported mode in v0.0.1)
- `user_password` (string, required if enabled): Password for opening PDF
- `owner_password` (string, optional): Admin password for changing permissions
- `crypto_profile` (string): `"strong"` (AES-256), `"compat"` (AES-128), `"legacy"` (RC4-128), `"auto"` (maps to strong)
- `allow_print` (bool): Allow printing (default: true)
- `allow_copy` (bool): Allow text copying (default: true)
- `allow_modify` (bool): Allow modifications (default: false)

### Labels Configuration

#### Visible Labels

```json
{
  "labels": {
    "mode": "visible",
    "visible": {
      "text": "CONFIDENTIAL - Internal Use Only",
      "placement": "footer",
      "pages": "all"
    }
  }
}
```

**Fields:**
- `text` (string, required): Label text to display
- `placement` (string): `"header"`, `"footer"`
- `pages` (string): `"all"`, `"first"`, `"range"`
- `page_range` (string, optional): e.g., `"1-5,10,15-20"` (only if pages="range")

#### Invisible Labels

```json
{
  "labels": {
    "mode": "invisible",
    "invisible": {
      "enabled": true,
      "namespace": "com.example.classification"
    }
  }
}
```

**Fields:**
- `enabled` (bool, required): Enable invisible labels
- `namespace` (string, optional): Custom metadata namespace

### Provenance Configuration

```json
{
  "provenance": {
    "enabled": true,
    "document_id": "auto",
    "copy_id": "auto"
  }
}
```

**Fields:**
- `enabled` (bool, required): Enable provenance tracking
- `document_id` (string): `"auto"` (generate UUIDv4) or custom ID
- `copy_id` (string): `"auto"` (generate UUIDv4) or custom ID

### Tamper Detection Configuration

```json
{
  "tamper_detection": {
    "enabled": true,
    "hash_alg": "sha256",
    "hash_profile": "objects_only"
  }
}
```

**Fields:**
- `enabled` (bool, required): Enable tamper detection
- `hash_alg` (string): `"sha256"` (only supported in v0.0.1)
- `hash_profile` (string): `"objects_only"` (recommended), `"content_streams"`, `"external"`

### Acknowledgment Configuration

```json
{
  "ack": {
    "required": true,
    "text": "OSS_DEFAULT",
    "viewer_dependent": true
  }
}
```

**Fields:**
- `required` (bool): Require acknowledgment
- `text` (string): `"OSS_DEFAULT"` (fixed in v0.0.1)
- `viewer_dependent` (bool): Acknowledge viewer dependency (emits W003 if true)

---

## Go Engine CLI

### Command: `secure`

Secure a PDF according to a policy.

```bash
securepdf-engine secure \
  --in <input-pdf> \
  --out <output-pdf> \
  --policy <policy-json> \
  --receipt <receipt-json> \
  [--engine-opt key=value]...
```

**Required Flags:**
- `--in`: Path to input PDF file
- `--out`: Path to output secured PDF file
- `--policy`: Path to policy JSON file
- `--receipt`: Path to receipt JSON output file

**Optional Flags:**
- `--engine-opt`: Engine runtime option (repeatable)

### Engine Options

Pass runtime options with `--engine-opt`:

```bash
--engine-opt reject_weak_crypto=true \
--engine-opt timeout_ms=30000 \
--engine-opt max_input_mb=100 \
--engine-opt max_memory_mb=256
```

**Available Options:**
- `reject_weak_crypto` (true/false): Reject legacy crypto profiles (default: false)
- `timeout_ms` (number): Processing timeout in milliseconds (default: 60000)
- `max_input_mb` (number): Maximum input file size in MB (default: 200)
- `max_memory_mb` (number): Maximum memory usage in MB (default: 512)

### Exit Codes

- `0`: Success
- `2`: Policy invalid
- `3`: Input invalid
- `4`: Transformation failed
- `5`: Output write failed
- `6`: Runtime limit exceeded

---

## Python SDK

### Core API

#### `secure_pdf()`

Secure a single PDF.

```python
from securepdf import secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))
receipt = secure_pdf("input.pdf", "output.pdf", policy)

if receipt.ok:
    print(f"Success! Document ID: {receipt.document_id}")
else:
    print(f"Failed: {receipt.error.message}")
```

**Parameters:**
- `input_path` (str | Path): Input PDF file path
- `output_path` (str | Path): Output PDF file path
- `policy` (Policy): Security policy
- `engine_bin` (str | Path, optional): Path to engine binary (default: "securepdf-engine")
- `engine_opts` (dict[str, str], optional): Engine runtime options

**Returns:** `Receipt` object

**Raises:**
- `SecurePDFEngineException`: Engine not found or failed
- `SecurePDF*Error`: Specific error based on error code (E001-E012)

#### `batch_secure_pdf()`

Secure multiple PDFs in parallel.

```python
from securepdf import batch_secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))

pairs = [
    ("doc1.pdf", "secured1.pdf"),
    ("doc2.pdf", "secured2.pdf"),
    ("doc3.pdf", "secured3.pdf"),
]

receipts = batch_secure_pdf(pairs, policy, max_workers=4)

for i, receipt in enumerate(receipts):
    print(f"PDF {i+1}: {'✅' if receipt.ok else '❌'}")
```

**Parameters:**
- `pdf_pairs` (List[Tuple[str, str]]): List of (input, output) path tuples
- `policy` (Policy): Security policy (shared across all PDFs)
- `engine_binary_path` (str, optional): Path to engine binary
- `engine_options` (dict, optional): Engine runtime options
- `max_workers` (int): Maximum concurrent workers (default: 4)

**Returns:** `List[Receipt]` in same order as input

### CLI Wrapper

```bash
python -m securepdf secure \
  --in input.pdf \
  --out output.pdf \
  --policy policy.json \
  --receipt receipt.json \
  --engine-opt reject_weak_crypto=true
```

**Show help:**
```bash
python -m securepdf --help
python -m securepdf secure --help
```

**Show version:**
```bash
python -m securepdf --version
```

---

## Common Use Cases

### 1. Simple Encryption

Encrypt a PDF with a password.

**Policy:**
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "MySecretPassword"
  }
}
```

**Python:**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig

policy = Policy(encryption=EncryptionConfig(
    enabled=True,
    user_password="MySecretPassword"
))

receipt = secure_pdf("doc.pdf", "secured-doc.pdf", policy)
```

### 2. Encryption + Visible Label

Add a footer label to all pages.

**Policy:**
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "secret"
  },
  "labels": {
    "mode": "visible",
    "visible": {
      "text": "CONFIDENTIAL - Internal Use Only",
      "placement": "footer",
      "pages": "all"
    }
  }
}
```

**Python:**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig, LabelsConfig, VisibleLabel

policy = Policy(
    encryption=EncryptionConfig(enabled=True, user_password="secret"),
    labels=LabelsConfig(
        mode="visible",
        visible=VisibleLabel(
            text="CONFIDENTIAL - Internal Use Only",
            placement="footer",
            pages="all"
        )
    )
)

receipt = secure_pdf("doc.pdf", "secured-doc.pdf", policy)
```

### 3. Full Provenance Tracking

Track document with unique IDs and tamper detection.

**Policy:**
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": true,
    "mode": "password",
    "user_password": "secret"
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

**Python:**
```python
from securepdf import secure_pdf, Policy, EncryptionConfig, ProvenanceConfig, TamperDetectionConfig

policy = Policy(
    encryption=EncryptionConfig(enabled=True, user_password="secret"),
    provenance=ProvenanceConfig(enabled=True, document_id="auto", copy_id="auto"),
    tamper_detection=TamperDetectionConfig(enabled=True, hash_alg="sha256")
)

receipt = secure_pdf("doc.pdf", "secured-doc.pdf", policy)

print(f"Document ID: {receipt.document_id}")
print(f"Copy ID: {receipt.copy_id}")
print(f"Content Hash: {receipt.input_content_hash}")
```

### 4. Batch Processing

Secure multiple PDFs with the same policy.

**Python:**
```python
from securepdf import batch_secure_pdf, Policy, EncryptionConfig
from pathlib import Path

policy = Policy(encryption=EncryptionConfig(enabled=True, user_password="secret"))

# Find all PDFs in a directory
input_dir = Path("documents")
output_dir = Path("secured")
output_dir.mkdir(exist_ok=True)

pairs = [
    (str(pdf), str(output_dir / pdf.name))
    for pdf in input_dir.glob("*.pdf")
]

print(f"Processing {len(pairs)} PDFs...")
receipts = batch_secure_pdf(pairs, policy, max_workers=4)

# Summary
success = sum(1 for r in receipts if r.ok)
failed = len(receipts) - success
print(f"✅ Success: {success}, ❌ Failed: {failed}")
```

### 5. No Encryption (Labels Only)

Apply labels without encryption.

**Policy:**
```json
{
  "policy_version": "1.0",
  "encryption": {
    "enabled": false
  },
  "labels": {
    "mode": "visible",
    "visible": {
      "text": "DRAFT - For Review Only",
      "placement": "footer",
      "pages": "all"
    }
  }
}
```

---

## Receipt Structure

Every transformation produces a JSON receipt.

### Success Receipt Example

```json
{
  "ok": true,
  "engine_version": "0.0.1",
  "policy_version": "1.0",
  "timestamp": "2026-02-27T10:30:00Z",
  "input_sha256": "abc123...",
  "output_sha256": "def456...",
  "input_content_hash": "789ghi...",
  "document_id": "doc-550e8400-e29b-41d4-a716-446655440000",
  "copy_id": "copy-6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "warnings": [],
  "error": null
}
```

### Error Receipt Example

```json
{
  "ok": false,
  "engine_version": "0.0.1",
  "policy_version": "1.0",
  "timestamp": "2026-02-27T10:30:00Z",
  "warnings": [],
  "error": {
    "code": "E002",
    "message": "Input PDF is corrupted or invalid",
    "details": {
      "file": "input.pdf",
      "reason": "PDF header not found"
    }
  }
}
```

### Receipt Fields

- `ok` (bool): True if transformation succeeded
- `engine_version` (string): Engine version used
- `policy_version` (string): Policy schema version
- `timestamp` (string): ISO 8601 timestamp
- `input_sha256` (string): SHA-256 hash of input file
- `output_sha256` (string): SHA-256 hash of output file
- `input_content_hash` (string): Content hash for tamper detection
- `document_id` (string): Document identifier (if provenance enabled)
- `copy_id` (string): Copy identifier (if provenance enabled)
- `warnings` (array): List of warnings (W001-W008)
- `error` (object): Error details (if ok=false)

---

## Error Handling

### Error Codes (E001-E012, E099)

| Code | Meaning | Python Exception |
|------|---------|------------------|
| E001 | Policy invalid or malformed | `SecurePDFPolicyInvalidError` |
| E002 | Input PDF invalid or corrupted | `SecurePDFInputInvalidError` |
| E003 | Input PDF unsupported features | `SecurePDFInputUnsupportedError` |
| E004 | PDF encryption failed | `SecurePDFEncryptionError` |
| E005 | Label application failed | `SecurePDFLabelError` |
| E006 | Provenance embedding failed | `SecurePDFProvenanceError` |
| E007 | Tamper hash computation failed | `SecurePDFTamperHashError` |
| E008 | Output file write failed | `SecurePDFOutputError` |
| E009 | Processing timeout exceeded | `SecurePDFTimeoutError` |
| E010 | Memory limit exceeded | `SecurePDFMemoryLimitError` |
| E011 | Input file read failed | `SecurePDFInputReadError` |
| E012 | Weak crypto rejected | `SecurePDFWeakCryptoRejectedError` |
| E099 | Internal error | `SecurePDFInternalError` |

### Python Exception Handling

```python
from securepdf import secure_pdf, Policy
from securepdf.exception import (
    SecurePDFPolicyInvalidError,
    SecurePDFInputInvalidError,
    SecurePDFEngineException,
)

try:
    receipt = secure_pdf("input.pdf", "output.pdf", policy)

    if receipt.ok:
        print("Success!")
    else:
        print(f"Failed: {receipt.error.code} - {receipt.error.message}")

except SecurePDFPolicyInvalidError as e:
    print(f"Policy error: {e}")
except SecurePDFInputInvalidError as e:
    print(f"Input PDF error: {e}")
except SecurePDFEngineException as e:
    print(f"Engine error: {e}")
```

### Warning Codes (W001-W008)

| Code | Meaning |
|------|---------|
| W001 | Weak crypto profile requested (RC4-128) |
| W002 | Weak crypto rejected |
| W003 | Viewer-dependent acknowledgment |
| W004 | Unsupported PDF feature detected |
| W005 | Label partially applied |
| W006 | Provenance partially applied |
| W007 | Tamper hash embed failed |
| W008 | Unknown policy field detected |

Warnings are non-fatal and don't stop processing.

---

## Engine Options

### timeout_ms

Maximum processing time in milliseconds.

```bash
--engine-opt timeout_ms=30000  # 30 seconds
```

**Use cases:**
- Prevent hanging on corrupted PDFs
- Enforce SLA for batch processing
- Limit resource consumption

### max_input_mb

Maximum input file size in megabytes.

```bash
--engine-opt max_input_mb=50  # 50 MB limit
```

**Use cases:**
- Reject oversized PDFs
- Prevent memory exhaustion
- Enforce file size policies

### max_memory_mb

Maximum memory usage in megabytes (best-effort).

```bash
--engine-opt max_memory_mb=256  # 256 MB limit
```

**Use cases:**
- Prevent OOM in constrained environments
- Enforce resource quotas

### reject_weak_crypto

Reject weak cryptographic profiles.

```bash
--engine-opt reject_weak_crypto=true
```

**Use cases:**
- Enforce strong crypto policy
- Compliance requirements
- Security hardening

---

## Troubleshooting

### Engine Binary Not Found

**Error:**
```
Engine binary not found: securepdf-engine
```

**Solution:**
1. Build the engine: `cd engine && go build -o ../bin/securepdf-engine ./cmd/securepdf-engine`
2. Add to PATH: `export PATH=$PATH:/path/to/securepdf/bin`
3. Or specify full path: `--engine-bin /path/to/securepdf-engine`

### Policy Validation Error

**Error:**
```
E001: Policy invalid - encryption.user_password is required when enabled=true
```

**Solution:**
Check your policy file for required fields:
- `encryption.user_password` is required when `encryption.enabled=true`
- `policy_version` must be `"1.0"`
- Use valid enum values for `crypto_profile`, `placement`, etc.

### Input PDF Invalid

**Error:**
```
E002: Input PDF invalid or corrupted
```

**Solution:**
1. Verify PDF opens in a viewer (Adobe Reader, Preview, etc.)
2. Check file is not corrupted: `file input.pdf` should show "PDF document"
3. Try repairing PDF with qpdf: `qpdf --check input.pdf`

### Timeout Exceeded

**Error:**
```
E009: Processing timeout exceeded
```

**Solution:**
- Increase timeout: `--engine-opt timeout_ms=120000` (2 minutes)
- Check PDF complexity (large file, many pages, complex graphics)
- Disable features if not needed (labels, provenance)

### Memory Limit Exceeded

**Error:**
```
E010: Memory limit exceeded
```

**Solution:**
- Increase limit: `--engine-opt max_memory_mb=1024`
- Reduce PDF size or complexity
- Process in smaller batches

---

## Next Steps

- **API Reference**: See inline docstrings (Go godoc, Python docstrings)
- **Architecture**: Read `docs/pdf-secure-architecture-final.md`
- **Engine Contract**: Read `docs/engine-contract.md`
- **CHANGELOG**: See `CHANGELOG.md` for complete feature list
- **Examples**: Check `examples/` directory (if available)

---

**Questions or Issues?** File a bug report at https://github.com/ravishtiwari/pdf-secure/issues
