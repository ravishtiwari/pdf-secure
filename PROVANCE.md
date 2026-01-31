# PROVANCE

This document covers provenance support in SecurePDF and how to test it using the
engine and Python SDK. (The file name matches the requested spelling.)

## Provenance overview

When provenance is enabled, the engine writes two identifiers into the PDF
metadata:

- `SecurePDF_DocumentID`
- `SecurePDF_CopyID`

These identifiers are also returned in the receipt as `document_id` and `copy_id`.
If the policy uses `"auto"`, the engine generates UUIDv4-based IDs prefixed with
`doc-` and `copy-`.

## Policy configuration

Provenance config is part of the policy:

```json
{
  "policy_version": "1.0",
  "encryption": { "enabled": false },
  "provenance": {
    "enabled": true,
    "document_id": "auto",
    "copy_id": "auto"
  }
}
```

Notes:
- `document_id` and `copy_id` can be `"auto"` or a custom string.
- Provenance can be combined with encryption; metadata is still written, but the
  PDF must be opened with the password to read it.

Sample policies (engine testdata):
- `engine/testdata/policies/valid/05-provenance-auto-ids.json`
- `engine/testdata/policies/valid/09-provenance-custom-ids.json`
- `engine/testdata/policies/valid/10-provenance-encrypted.json`

## Python test script (scripts/test_provenance.py)

This script runs the engine through the Python SDK and optionally verifies that
metadata matches the receipt. It lives at `scripts/test_provenance.py`.

### Run (unencrypted)

```bash
. .venv/bin/activate
python scripts/test_provenance.py \
  --in engine/test-pdfs/sample-input.pdf \
  --out /tmp/provenance-out.pdf
```

### Run (encrypted)

```bash
. .venv/bin/activate
python scripts/test_provenance.py \
  --in engine/test-pdfs/sample-input.pdf \
  --out /tmp/provenance-out.pdf \
  --password "LabelTest123!"
```

### Verify metadata (requires pypdf)

```bash
. .venv/bin/activate
python -m pip install pypdf

python scripts/test_provenance.py \
  --in engine/test-pdfs/sample-input.pdf \
  --out /tmp/provenance-out.pdf \
  --verify-metadata
```

When `--verify-metadata` is used, the script will read PDF metadata and compare
`/SecurePDF_DocumentID` and `/SecurePDF_CopyID` with the receipt values. If the
PDF is encrypted, pass `--password` so metadata can be read.

### Encrypted input PDFs

The engine cannot process already-encrypted PDFs. If your input is encrypted,
use `--input-password` and the script will decrypt to a temporary file (requires
`pypdf`) before running the engine. If `qpdf` is available, the script will use
it to decrypt (recommended when `pypdf` lacks crypto dependencies).

If you see a `cryptography>=3.1 is required for AES algorithm` error, either:
- install `cryptography` into the active environment, or
- install `qpdf` and let the script use it for decryption.

### Validation-only mode

If you just want to validate provenance metadata on an existing PDF without
running the engine, use `--validate-only` with `--verify-metadata`:

```bash
python scripts/test_provenance.py \
  --in sample-output-provance.pdf \
  --verify-metadata \
  --validate-only \
  --input-password ProvEncrypt123!
```

Notes:
- Metadata validation works with `pypdf` or `qpdf`. If `pypdf` is missing or
  lacks crypto dependencies, install `qpdf` and the script will use it.

## Targeted tests

The Python test suite includes an end-to-end provenance test:

- `python/tests/test_provenance_e2e.py`

It:
- Runs the engine through the Python SDK.
- Confirms `document_id` and `copy_id` are present in the receipt.
- Validates UUIDv4-based format for auto-generated IDs.

Run it with:

```bash
cd python
python -m pytest tests/test_provenance_e2e.py -v
```

The test is skipped if `bin/securepdf-engine` is missing.

## Engine CLI usage

You can also run provenance from the CLI:

```bash
bin/securepdf-engine secure \
  --in engine/test-pdfs/sample-input.pdf \
  --out /tmp/provenance-out.pdf \
  --policy engine/testdata/policies/valid/05-provenance-auto-ids.json \
  --receipt /tmp/receipt.json
```

Encrypted provenance example:

```bash
bin/securepdf-engine secure \
  --in engine/test-pdfs/sample-input.pdf \
  --out /tmp/provenance-out.pdf \
  --policy engine/testdata/policies/valid/10-provenance-encrypted.json \
  --receipt /tmp/receipt.json
```

## Troubleshooting

- If IDs are missing from the receipt, ensure `provenance.enabled` is `true`.
- If metadata is not readable, verify the PDF password is supplied when
  encrypted.
- If the script cannot import `pypdf`, install it in the current environment:
  `python -m pip install pypdf`.
