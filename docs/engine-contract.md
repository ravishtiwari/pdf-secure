# SecurePDF Engine Contract

**Version:** 1.0
**Engine Version:** 0.0.1
**Last Updated:** February 27, 2026

---

## Overview

This document defines the public contract for the SecurePDF Go Engine (`securepdf-engine`). It specifies the command-line interface, input policy schema, output receipt schema, error codes, and runtime options.

### Engine Model

The SecurePDF engine is a stateless transformation tool:

```
Input PDF + Security Policy → Secured PDF + Transformation Receipt
```

The engine processes PDFs locally without network access or persistent state.

---

## CLI Interface

### Command: `secure`

Transforms a PDF according to a security policy.

**Syntax:**
```bash
securepdf-engine secure \
  --in <input.pdf> \
  --out <secured.pdf> \
  --policy <policy.json> \
  --receipt <receipt.json> \
  [--engine-opt <key=value>]...
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--in` | Yes | Path to input PDF file |
| `--out` | Yes | Path to output secured PDF file |
| `--policy` | Yes | Path to policy JSON file |
| `--receipt` | Yes | Path to output receipt JSON file |
| `--engine-opt` | No | Engine runtime option (repeatable) |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| `0` | Success (receipt `ok=true`) |
| `2` | Policy invalid |
| `3` | Input PDF invalid or unsupported |
| `4` | Transformation failed |
| `5` | Output write failed |
| `6` | Runtime limit exceeded (timeout or memory) |

**Receipt Generation:**

The engine writes a receipt JSON file for all transformations, including failures. When the exit code is non-zero, the receipt contains `ok=false` and structured error information.

---

## Policy Schema

### Structure

```json
{
  "policy_version": "1.0",
  "encryption": { ... },
  "ack": { ... },
  "labels": { ... },
  "provenance": { ... },
  "tamper_detection": { ... }
}
```

---

### `policy_version`

**Type:** String
**Required:** Yes
**Valid Values:** `"1.0"`

Specifies the policy schema version.

---

### `encryption`

Controls PDF encryption and permissions.

**Schema:**
```json
{
  "enabled": true,
  "mode": "password",
  "user_password": "string",
  "owner_password": "string",
  "allow_print": false,
  "allow_copy": false,
  "allow_modify": false,
  "crypto_profile": "strong"
}
```

**Fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | boolean | Yes | - | Enable encryption |
| `mode` | string | No | `"password"` | Encryption mode (v0.0.1: `"password"` only) |
| `user_password` | string | Yes* | - | Password to open PDF (*required if enabled=true) |
| `owner_password` | string | No | random | Admin password (auto-generated if omitted) |
| `allow_print` | boolean | No | `false` | Allow printing |
| `allow_copy` | boolean | No | `false` | Allow text/image copying |
| `allow_modify` | boolean | No | `false` | Allow document modification |
| `crypto_profile` | string | No | `"strong"` | Encryption strength |

**Crypto Profiles:**

| Profile | Algorithm | Security Level |
|---------|-----------|----------------|
| `strong` | AES-256 | Recommended (default) |
| `compat` | AES-128 | Broader viewer support |
| `legacy` | RC4-128 | Legacy systems only (emits W001) |
| `auto` | AES-256 | Alias for `strong` |

**Warnings:**
- Using `legacy` profile emits warning W001 (WEAK_CRYPTO_REQUESTED)
- The `reject_weak_crypto` engine option blocks legacy profiles and fails with E001 (POLICY_INVALID)

---

### `ack`

Custodianship acknowledgment configuration.

**Schema:**
```json
{
  "required": true,
  "text": "OSS_DEFAULT",
  "viewer_dependent": true
}
```

**Fields:**

| Field | Type | Required | Valid Values | Description |
|-------|------|----------|--------------|-------------|
| `required` | boolean | No | `true`/`false` | Require acknowledgment |
| `text` | string | No | `"OSS_DEFAULT"` | Acknowledgment text (v0.0.1: fixed value) |
| `viewer_dependent` | boolean | No | `true`/`false` | Acknowledge viewer dependency (emits W003) |

**Notes:**
- In v0.0.1, `text` accepts only `"OSS_DEFAULT"`
- Setting `viewer_dependent=true` emits warning W003

---

### `labels`

Document classification labels (visible or invisible).

**Schema:**
```json
{
  "mode": "visible",
  "visible": {
    "text": "CONFIDENTIAL",
    "placement": "footer",
    "pages": "all",
    "page_range": "1-3,8,10-12"
  },
  "invisible": {
    "enabled": true,
    "namespace": "com.example.classification"
  }
}
```

**Mode Values:**

| Mode | Description |
|------|-------------|
| `visible` | Add visible text labels to pages |
| `invisible` | Embed metadata labels |
| `off` | No labels applied |

**Visible Label Fields:**

| Field | Type | Required | Valid Values | Description |
|-------|------|----------|--------------|-------------|
| `text` | string | Yes* | - | Label text (*required if mode=visible) |
| `placement` | string | No | `footer`, `header` | Label position |
| `pages` | string | No | `all`, `first`, `range` | Page selection |
| `page_range` | string | No | `"1-5,10,15-20"` | Page range (required if pages=range) |

**Invisible Label Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | Yes* | Enable invisible labels (*required if mode=invisible) |
| `namespace` | string | No | Custom metadata namespace |

---

### `provenance`

Document and copy tracking identifiers.

**Schema:**
```json
{
  "enabled": true,
  "document_id": "auto",
  "copy_id": "auto"
}
```

**Fields:**

| Field | Type | Required | Valid Values | Description |
|-------|------|----------|--------------|-------------|
| `enabled` | boolean | Yes | `true`/`false` | Enable provenance tracking |
| `document_id` | string | No | `auto` or custom | Document identifier (UUIDv4 if `auto`) |
| `copy_id` | string | No | `auto` or custom | Copy identifier (UUIDv4 if `auto`) |

**Behavior:**
- When `enabled=true`, IDs are embedded in PDF metadata
- `auto` generates UUIDv4 identifiers
- Custom IDs accept any string value

---

### `tamper_detection`

Content integrity hashing for tamper detection.

**Schema:**
```json
{
  "enabled": true,
  "hash_alg": "sha256",
  "hash_profile": "objects_only"
}
```

**Fields:**

| Field | Type | Required | Valid Values | Description |
|-------|------|----------|--------------|-------------|
| `enabled` | boolean | Yes | `true`/`false` | Enable tamper detection |
| `hash_alg` | string | No | `sha256` | Hash algorithm (v0.0.1: SHA-256 only) |
| `hash_profile` | string | No | See below | What content to hash |

**Hash Profiles:**

| Profile | Description |
|---------|-------------|
| `objects_only` | Hash PDF objects (default, stable across metadata updates) |
| `content_streams` | Hash content streams only |
| `external` | Hash entire file bytes (legacy mode) |

**Behavior:**
- Hash is embedded in PDF metadata
- Receipt field `input_content_hash` contains the computed hash

---

## Receipt Schema

### Structure

**Success Receipt:**
```json
{
  "ok": true,
  "engine_version": "0.0.1",
  "policy_version": "1.0",
  "timestamp": "2026-02-27T10:30:00Z",
  "document_id": "doc-550e8400-e29b-41d4-a716-446655440000",
  "copy_id": "copy-6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "input_sha256": "abc123...",
  "output_sha256": "def456...",
  "input_content_hash": "789ghi...",
  "warnings": [
    {"code": "W001", "message": "Weak crypto profile requested"}
  ],
  "error": null
}
```

**Error Receipt:**
```json
{
  "ok": false,
  "engine_version": "0.0.1",
  "policy_version": "1.0",
  "timestamp": "2026-02-27T10:30:00Z",
  "warnings": [],
  "error": {
    "code": "E001",
    "message": "encryption.user_password is required when enabled=true",
    "details": {
      "field": "encryption.user_password"
    }
  }
}
```

---

### Required Fields

All receipts contain:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | `true` if transformation succeeded |
| `engine_version` | string | Engine version that performed transformation |
| `policy_version` | string | Policy schema version used |
| `timestamp` | string | ISO 8601 timestamp (RFC 3339 UTC) |
| `warnings` | array | Warning objects (may be empty) |
| `error` | object/null | Error details (null if ok=true) |

---

### Success Fields

Present when `ok=true`:

| Field | Type | Description |
|-------|------|-------------|
| `input_sha256` | string | SHA-256 hash of input file |
| `output_sha256` | string | SHA-256 hash of output file |
| `input_content_hash` | string | Tamper detection hash (if enabled) |
| `document_id` | string | Document identifier (if provenance enabled) |
| `copy_id` | string | Copy identifier (if provenance enabled) |

---

### Warning Object

```json
{
  "code": "W001",
  "message": "Human-readable warning message"
}
```

---

### Error Object

```json
{
  "code": "E001",
  "message": "Human-readable error message",
  "details": {
    "field": "encryption.user_password",
    "reason": "required when enabled=true"
  }
}
```

The `details` object is optional and provides structured error context.

---

## Warning Codes

Warnings are non-fatal and transformation continues.

| Code | Name | Description |
|------|------|-------------|
| `W001` | `WEAK_CRYPTO_REQUESTED` | Weak crypto profile requested (proceeding with reduced security) |
| `W002` | `WEAK_CRYPTO_REJECTED` | Reserved; not emitted in v0.0.1 |
| `W003` | `VIEWER_DEPENDENT_ACK` | Acknowledgment mechanism depends on PDF viewer |
| `W004` | `UNSUPPORTED_PDF_FEATURE` | Input PDF contains unsupported features |
| `W005` | `LABEL_PARTIALLY_APPLIED` | Labels could not be applied to all requested pages |
| `W006` | `PROVENANCE_PARTIALLY_APPLIED` | Provenance data could not be fully embedded |
| `W007` | `TAMPER_HASH_EMBED_FAILED` | Tamper hash computed but could not be embedded |
| `W008` | `UNKNOWN_POLICY_FIELD` | Policy contains unknown fields (ignored) |

---

## Error Codes

Errors are fatal and transformation fails.

| Code | Name | Description |
|------|------|-------------|
| `E001` | `POLICY_INVALID` | Policy is invalid or malformed |
| `E002` | `INPUT_PDF_INVALID` | Input file is not a valid PDF |
| `E003` | `INPUT_PDF_UNSUPPORTED` | Input PDF uses unsupported features |
| `E004` | `ENCRYPTION_FAILED` | PDF encryption failed |
| `E005` | `LABEL_FAILED` | Label application failed |
| `E006` | `PROVENANCE_FAILED` | Provenance embedding failed |
| `E007` | `TAMPER_HASH_FAILED` | Tamper detection hash computation failed |
| `E008` | `OUTPUT_WRITE_FAILED` | Output file could not be written |
| `E009` | `RUNTIME_TIMEOUT` | Transformation exceeded time limit |
| `E010` | `RUNTIME_MEMORY_LIMIT` | Transformation exceeded memory limit |
| `E011` | `INPUT_READ_FAILED` | Input file could not be read |
| `E012` | `WEAK_CRYPTO_REJECTED` | Weak crypto profile rejected (when reject_weak_crypto=true) |
| `E099` | `INTERNAL_ERROR` | Unexpected internal error |

---

## Engine Runtime Options

Runtime options control engine behavior independently of the security policy.

**Usage:**
```bash
--engine-opt <key>=<value>
```

**Available Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `reject_weak_crypto` | boolean | `false` | Reject `legacy` crypto profile (raises E001 POLICY_INVALID) |
| `timeout_ms` | integer | `60000` | Processing timeout in milliseconds |
| `max_input_mb` | integer | `200` | Maximum input file size in megabytes |
| `max_memory_mb` | integer | `512` | Maximum memory usage in megabytes |

**Example:**
```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json \
  --engine-opt reject_weak_crypto=true \
  --engine-opt timeout_ms=30000 \
  --engine-opt max_input_mb=100
```

---

## Versioning and Compatibility

### Policy Version

The `policy_version` field uses semantic versioning:
- **Major version** increments indicate breaking changes
- **Minor version** increments indicate backward-compatible additions

Version `1.0` is the initial policy schema.

### Receipt Schema

Receipt fields follow additive evolution:
- New fields may be added in future versions
- Existing fields will not be removed or renamed
- Clients should ignore unknown fields

### Engine Version

The `engine_version` field in receipts indicates the engine binary version that performed the transformation. This follows semantic versioning independently of the policy version.

### Forward Compatibility

The engine ignores unknown policy fields and emits warning W008. This allows newer policy files to work with older engines gracefully.

---

## Changelog

### Version 1.0 (Engine v0.0.1)
- Initial contract specification
- Policy schema v1.0
- 13 error codes (E001-E012, E099)
- 8 warning codes (W001-W008)
- 4 runtime options
