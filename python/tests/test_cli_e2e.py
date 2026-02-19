"""E2E tests for CLI wrapper."""

import subprocess
import json
import tempfile
from pathlib import Path
import pytest


def test_cli_secure_e2e(tmp_path):
    """Test CLI secure command end-to-end."""
    # Paths
    input_pdf = (
        Path(__file__).parent.parent.parent
        / "engine"
        / "test-pdfs"
        / "sample-input.pdf"
    )
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    # Create minimal policy
    policy = {"policy_version": "1.0", "encryption": {"enabled": False}}
    policy_path.write_text(json.dumps(policy))

    # Run CLI
    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,  # Run from python/ directory
    )

    # Check success
    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    assert output_pdf.exists(), "Output PDF was not created"
    assert receipt_path.exists(), "Receipt was not created"

    # Verify receipt
    receipt_data = json.loads(receipt_path.read_text())
    assert receipt_data["ok"] is True


def test_cli_missing_args():
    """Test that CLI fails with proper error when args are missing."""
    result = subprocess.run(
        ["python", "-m", "securepdf", "secure"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert result.returncode != 0, "CLI should fail with missing arguments"
    assert "required" in result.stderr.lower() or "error" in result.stderr.lower()


def test_cli_invalid_policy(tmp_path):
    """Test that CLI fails gracefully with invalid policy."""
    input_pdf = (
        Path(__file__).parent.parent.parent
        / "engine"
        / "test-pdfs"
        / "sample-input.pdf"
    )
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    # Create invalid policy
    policy_path.write_text("invalid json{")

    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert result.returncode != 0, "CLI should fail with invalid policy"


def test_cli_with_engine_options(tmp_path):
    """Test CLI with engine options."""
    input_pdf = (
        Path(__file__).parent.parent.parent
        / "engine"
        / "test-pdfs"
        / "sample-input.pdf"
    )
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    # Create policy
    policy = {"policy_version": "1.0", "encryption": {"enabled": False}}
    policy_path.write_text(json.dumps(policy))

    # Run CLI with engine options
    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
            "--engine-opt",
            "timeout_ms=120000",
            "--engine-opt",
            "max_input_mb=300",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Check success
    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    assert output_pdf.exists(), "Output PDF was not created"
    assert receipt_path.exists(), "Receipt was not created"


def test_cli_missing_input_file(tmp_path):
    """Test that CLI fails when input file doesn't exist."""
    input_pdf = tmp_path / "nonexistent.pdf"
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    # Create policy
    policy = {"policy_version": "1.0", "encryption": {"enabled": False}}
    policy_path.write_text(json.dumps(policy))

    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert result.returncode != 0, "CLI should fail with missing input file"


def test_cli_missing_policy_file(tmp_path):
    """Test that CLI fails when policy file doesn't exist."""
    input_pdf = (
        Path(__file__).parent.parent.parent
        / "engine"
        / "test-pdfs"
        / "sample-input.pdf"
    )
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "nonexistent-policy.json"
    receipt_path = tmp_path / "receipt.json"

    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert result.returncode == 2, "CLI should exit with code 2 for missing policy file"
    assert "not found" in result.stderr.lower()


def test_cli_with_encryption(tmp_path):
    """Test CLI with encryption enabled."""
    input_pdf = (
        Path(__file__).parent.parent.parent
        / "engine"
        / "test-pdfs"
        / "sample-input.pdf"
    )
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    # Create policy with encryption
    policy = {
        "policy_version": "1.0",
        "encryption": {
            "enabled": True,
            "mode": "password",
            "user_password": "user123",
            "owner_password": "owner123",
            "crypto_profile": "strong",
        },
    }
    policy_path.write_text(json.dumps(policy))

    # Run CLI
    result = subprocess.run(
        [
            "python",
            "-m",
            "securepdf",
            "secure",
            "--in",
            str(input_pdf),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    # Check success
    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    assert output_pdf.exists(), "Output PDF was not created"
    assert receipt_path.exists(), "Receipt was not created"

    # Verify receipt
    receipt_data = json.loads(receipt_path.read_text())
    assert receipt_data["ok"] is True


def test_cli_no_command():
    """Test that CLI prints help when no command is provided."""
    result = subprocess.run(
        ["python", "-m", "securepdf"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert (
        result.returncode == 1
    ), "CLI should exit with code 1 when no command provided"
    # Help text should be printed (either to stdout or stderr)
    output = result.stdout + result.stderr
    assert "securepdf" in output.lower() or "usage" in output.lower()
