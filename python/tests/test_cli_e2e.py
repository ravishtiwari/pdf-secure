"""E2E tests for CLI wrapper (`python -m securepdf`)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _engine_bin() -> Path:
    return _repo_root() / "bin" / "securepdf-engine"


def _sample_input() -> Path:
    return _repo_root() / "engine" / "test-pdfs" / "sample-input.pdf"


def _cli(*args: str) -> list[str]:
    """Build a CLI command with the engine binary path pre-set."""
    return [
        sys.executable,
        "-m",
        "securepdf",
        *args,
        "--engine-bin",
        str(_engine_bin()),
    ]


skip_no_engine = pytest.mark.skipif(
    not _engine_bin().exists(),
    reason="securepdf-engine binary missing; build it before running this test",
)


@skip_no_engine
def test_cli_secure_e2e(tmp_path: Path) -> None:
    """Test CLI secure command end-to-end."""
    output_pdf = tmp_path / "output.pdf"
    policy_path = tmp_path / "policy.json"
    receipt_path = tmp_path / "receipt.json"

    policy_path.write_text(
        json.dumps({"policy_version": "1.0", "encryption": {"enabled": False}})
    )

    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(_sample_input()),
            "--out",
            str(output_pdf),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )

    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    assert output_pdf.exists(), "Output PDF was not created"
    assert receipt_path.exists(), "Receipt was not created"
    assert json.loads(receipt_path.read_text())["ok"] is True


def test_cli_missing_args() -> None:
    """Test that CLI fails with proper error when required args are missing."""
    result = subprocess.run(
        [sys.executable, "-m", "securepdf", "secure"],
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode != 0
    assert "required" in result.stderr.lower() or "error" in result.stderr.lower()


def test_cli_no_command() -> None:
    """Test that CLI exits non-zero and prints help when no command given."""
    result = subprocess.run(
        [sys.executable, "-m", "securepdf"],
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "securepdf" in output.lower() or "usage" in output.lower()


@skip_no_engine
def test_cli_invalid_policy(tmp_path: Path) -> None:
    """Test that CLI fails gracefully with invalid policy JSON."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("invalid json{")

    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(_sample_input()),
            "--out",
            str(tmp_path / "output.pdf"),
            "--policy",
            str(policy_path),
            "--receipt",
            str(tmp_path / "receipt.json"),
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode != 0


@skip_no_engine
def test_cli_missing_policy_file(tmp_path: Path) -> None:
    """Test that CLI exits 2 when policy file doesn't exist."""
    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(_sample_input()),
            "--out",
            str(tmp_path / "output.pdf"),
            "--policy",
            str(tmp_path / "nonexistent-policy.json"),
            "--receipt",
            str(tmp_path / "receipt.json"),
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode == 2
    assert "not found" in result.stderr.lower()


@skip_no_engine
def test_cli_missing_input_file(tmp_path: Path) -> None:
    """Test that CLI fails when input PDF doesn't exist."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"policy_version": "1.0", "encryption": {"enabled": False}})
    )

    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(tmp_path / "nonexistent.pdf"),
            "--out",
            str(tmp_path / "output.pdf"),
            "--policy",
            str(policy_path),
            "--receipt",
            str(tmp_path / "receipt.json"),
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode != 0


@skip_no_engine
def test_cli_with_engine_options(tmp_path: Path) -> None:
    """Test CLI with engine options."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"policy_version": "1.0", "encryption": {"enabled": False}})
    )

    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(_sample_input()),
            "--out",
            str(tmp_path / "output.pdf"),
            "--policy",
            str(policy_path),
            "--receipt",
            str(tmp_path / "receipt.json"),
            "--engine-opt",
            "timeout_ms=120000",
            "--engine-opt",
            "max_input_mb=300",
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode == 0, f"CLI failed: {result.stderr}"


@skip_no_engine
def test_cli_with_encryption(tmp_path: Path) -> None:
    """Test CLI with encryption enabled."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "policy_version": "1.0",
                "encryption": {
                    "enabled": True,
                    "mode": "password",
                    "user_password": "user123",
                    "owner_password": "owner123",
                    "crypto_profile": "strong",
                },
            }
        )
    )
    receipt_path = tmp_path / "receipt.json"

    result = subprocess.run(
        _cli(
            "secure",
            "--in",
            str(_sample_input()),
            "--out",
            str(tmp_path / "output.pdf"),
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ),
        capture_output=True,
        text=True,
        cwd=str(_repo_root() / "python"),
    )
    assert result.returncode == 0, f"CLI failed: {result.stderr}"
    assert json.loads(receipt_path.read_text())["ok"] is True
