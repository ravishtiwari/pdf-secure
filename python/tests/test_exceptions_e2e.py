"""E2E tests for typed exception hierarchy."""

import pytest
import tempfile
import os
from securepdf import (
    secure_pdf,
    Policy,
    EncryptionConfig,
    SecurePDFPolicyInvalidError,
    SecurePDFInputInvalidError,
)


def test_policy_invalid_raises_typed_exception(tmp_path):
    """Test that invalid policy raises SecurePDFPolicyInvalidError."""
    input_pdf = tmp_path / "input.pdf"
    output_pdf = tmp_path / "output.pdf"

    # Create a minimal valid PDF
    input_pdf.write_bytes(b"%PDF-1.4\n%%EOF")

    # Create invalid policy (missing required fields)
    policy = {"invalid": "policy"}

    with pytest.raises(SecurePDFPolicyInvalidError):
        secure_pdf(
            str(input_pdf),
            str(output_pdf),
            policy,  # Invalid - not a Policy object or valid dict
        )


def test_input_invalid_raises_typed_exception(tmp_path):
    """Test that invalid input raises SecurePDFInputInvalidError."""
    input_pdf = tmp_path / "not-a-pdf.txt"
    output_pdf = tmp_path / "output.pdf"

    # Create a non-PDF file
    input_pdf.write_text("This is not a PDF")

    # Create valid policy
    policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))

    with pytest.raises(SecurePDFInputInvalidError):
        secure_pdf(str(input_pdf), str(output_pdf), policy)
