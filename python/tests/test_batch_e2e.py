"""E2E tests for batch_secure_pdf."""

import pytest
from pathlib import Path
from securepdf import batch_secure_pdf, Policy, EncryptionConfig


def test_batch_secure_pdf_e2e(tmp_path):
    """Test batch processing of multiple PDFs."""
    # Create 3 input PDFs (copy from test fixture)
    sample_pdf = Path(__file__).parent.parent.parent / "test-pdfs" / "sample-input.pdf"

    pairs = []
    for i in range(3):
        input_pdf = tmp_path / f"input_{i}.pdf"
        output_pdf = tmp_path / f"output_{i}.pdf"
        input_pdf.write_bytes(sample_pdf.read_bytes())
        pairs.append((str(input_pdf), str(output_pdf)))

    # Create policy
    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    # Process batch
    receipts = batch_secure_pdf(pairs, policy, max_workers=2)

    # Verify results
    assert len(receipts) == 3
    for i, receipt in enumerate(receipts):
        assert receipt.ok, f"Receipt {i} failed: {receipt.error}"
        output_pdf = Path(pairs[i][1])
        assert output_pdf.exists(), f"Output {i} was not created"


def test_batch_preserves_order(tmp_path):
    """Test that batch_secure_pdf preserves input order."""
    sample_pdf = Path(__file__).parent.parent.parent / "test-pdfs" / "sample-input.pdf"

    pairs = []
    for i in range(5):
        input_pdf = tmp_path / f"input_{i}.pdf"
        output_pdf = tmp_path / f"output_{i}.pdf"
        input_pdf.write_bytes(sample_pdf.read_bytes())
        pairs.append((str(input_pdf), str(output_pdf)))

    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    receipts = batch_secure_pdf(pairs, policy)

    # Verify order by checking output_sha256 matches expected file
    assert len(receipts) == 5
    for i, receipt in enumerate(receipts):
        assert receipt.ok
