"""E2E tests for batch_secure_pdf."""

from __future__ import annotations

from pathlib import Path

import pytest

from securepdf import EncryptionConfig, Policy, batch_secure_pdf


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _engine_bin() -> Path:
    return _repo_root() / "bin" / "securepdf-engine"


def _sample_input() -> Path:
    return _repo_root() / "engine" / "test-pdfs" / "sample-input.pdf"


@pytest.mark.skipif(
    not _engine_bin().exists(),
    reason="securepdf-engine binary missing; build it before running this test",
)
def test_batch_secure_pdf_e2e(tmp_path: Path) -> None:
    """Test batch processing of multiple PDFs."""
    pairs = []
    for i in range(3):
        input_pdf = tmp_path / f"input_{i}.pdf"
        output_pdf = tmp_path / f"output_{i}.pdf"
        input_pdf.write_bytes(_sample_input().read_bytes())
        pairs.append((str(input_pdf), str(output_pdf)))

    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    receipts = batch_secure_pdf(
        pairs, policy, engine_binary_path=str(_engine_bin()), max_workers=2
    )

    assert len(receipts) == 3
    for i, receipt in enumerate(receipts):
        assert receipt.ok, f"Receipt {i} failed: {receipt.error}"
        assert Path(pairs[i][1]).exists(), f"Output {i} was not created"


@pytest.mark.skipif(
    not _engine_bin().exists(),
    reason="securepdf-engine binary missing; build it before running this test",
)
def test_batch_preserves_order(tmp_path: Path) -> None:
    """Test that batch_secure_pdf preserves input order."""
    pairs = []
    for i in range(5):
        input_pdf = tmp_path / f"input_{i}.pdf"
        output_pdf = tmp_path / f"output_{i}.pdf"
        input_pdf.write_bytes(_sample_input().read_bytes())
        pairs.append((str(input_pdf), str(output_pdf)))

    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    receipts = batch_secure_pdf(pairs, policy, engine_binary_path=str(_engine_bin()))

    assert len(receipts) == 5
    for receipt in receipts:
        assert receipt.ok
