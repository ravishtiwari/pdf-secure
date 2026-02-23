"""E2E tests for typed exception hierarchy."""

from __future__ import annotations

from pathlib import Path

import pytest

from securepdf import (
    secure_pdf,
    Policy,
    EncryptionConfig,
    SecurePDFPolicyInvalidError,
    SecurePDFInputInvalidError,
)


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
def test_policy_invalid_raises_typed_exception(tmp_path: Path) -> None:
    """Test that an invalid policy raises SecurePDFPolicyInvalidError (E001)."""
    output_pdf = tmp_path / "output.pdf"

    # Policy with unsupported version — engine returns E001
    policy = Policy(
        policy_version="99.0",
        encryption=EncryptionConfig(enabled=False),
    )

    with pytest.raises(SecurePDFPolicyInvalidError):
        secure_pdf(
            str(_sample_input()), str(output_pdf), policy, engine_bin=_engine_bin()
        )


@pytest.mark.skipif(
    not _engine_bin().exists(),
    reason="securepdf-engine binary missing; build it before running this test",
)
def test_input_invalid_raises_typed_exception(tmp_path: Path) -> None:
    """Test that a non-PDF input raises SecurePDFInputInvalidError (E002)."""
    input_pdf = tmp_path / "not-a-pdf.txt"
    output_pdf = tmp_path / "output.pdf"

    input_pdf.write_text("This is not a PDF file.")

    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    with pytest.raises(SecurePDFInputInvalidError):
        secure_pdf(str(input_pdf), str(output_pdf), policy, engine_bin=_engine_bin())
