# SecurePDF

SecurePDF is a lightweight, two-layer system designed to **secure PDF documents** according to an explicit **security policy**, with a strong technical and philosophical emphasis on **custodianship-by-access**.

The project is built around the principle that security is not just about encryption, but about making the recipient aware of their responsibility as a custodian of the information they access.

## 🛡️ Core Philosophy: Custodianship-by-Access

When a recipient opens a document secured by SecurePDF, the system aims to ensure they clearly understand:
- The document is intended specifically for them.
- They are the designated custodian of this specific copy.
- Sharing or misuse of the file makes them directly responsible for the breach.

SecurePDF focuses on **forensic accountability** and **clear intent** rather than impossible DRM or remote-kill switches.

## 🏗️ Architecture

SecurePDF uses a deliberate "Pure Engine" split to maximize performance, reliability, and ease of integration:

- **Go Engine (`securepdf-engine`)**: A high-performance, stateless core responsible for the **HOW**. It handles PDF parsing, AES-256 encryption, PBKDF2 key derivation, labeling primitives, and forensic metadata embedding.
- **Python SDK (`securepdf`)**: A developer-friendly layer responsible for the **WHAT**. It orchestrates policies, manages I/O sources/destinations, handles batching, and provides a high-level API for integration into existing stacks.

```text
PDF + Policy → [ Go Engine ] → Secured PDF + Structured Receipt
```

## ✨ Key Features (V1)

- **Strong Crypto Defaults**: AES-256 encryption with PBKDF2 (high iteration count) password derivation.
- **Forensic Tamper-Detection**: Original content hashes embedded directly into the secured PDF's metadata.
- **Provenance Embedding**: Tracking of `document_id`, `copy_id`, timestamps, and policy versions.
- **Visible & Invisible Labels**: Header/footer overlays and metadata-level watermarking.
- **Custodianship Messaging**: Built-in messaging to acknowledge terms of access (supported in compliant viewers).
- **Structured Receipts**: Every transformation produces a JSON receipt containing forensic audit data and integrity hashes.

## 📁 Project Structure

- `engine/`: The stateless Go transformation engine.
- `python/`: The Python SDK and orchestration layer.
- `docs/`: Architecture specifications and engine contracts.

## 🚀 Roadmap

- **V1.0 (Current)**: Secure Core (AES-256, Provenance, Stateless transformation).
- **V1.1**: Polish & Reliability (UTF-8 support, runtime guardrails, better validation).
- **V2.0**: Scale & Services (High-throughput worker mode, FastAPI service, Org policies).

---

*Note: SecurePDF is currently in active development (V1.0 Alpha).*

## 🔧 CLI Usage (Engine)

```bash
securepdf-engine secure \
  --in input.pdf \
  --out secured.pdf \
  --policy policy.json \
  --receipt receipt.json \
  --engine-opt reject_weak_crypto=true \
  --engine-opt timeout_ms=60000
```

Supported engine options:
- `reject_weak_crypto` (true|false)
- `timeout_ms` (milliseconds)
- `max_input_mb` (MB)
- `max_memory_mb` (MB)
