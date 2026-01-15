import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional
from .helpers.data_class import Policy, Receipt
from .exception import SecurePDFEngineException


def secure_pdf(
    input_path: str,
    output_path: str,
    policy: Policy,
    engine_bin: str = "securepdf-engine",
) -> Receipt:
    """
    Secures a PDF using the Go engine.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as policy_file:
        policy_file.write(policy.to_json())
        policy_path = policy_file.name

    with tempfile.NamedTemporaryFile(
        mode="r", suffix=".json", delete=False
    ) as receipt_file:
        receipt_path = receipt_file.name

    try:
        cmd = [
            engine_bin,
            "secure",
            "--in",
            input_path,
            "--out",
            output_path,
            "--policy",
            policy_path,
            "--receipt",
            receipt_path,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError as e:
            raise SecurePDFEngineException(
                f"Engine binary not found: {engine_bin}"
            ) from e

        if Path(receipt_path).exists():
            with open(receipt_path, "r") as f:
                data = json.load(f)
                return Receipt(**data)

        raise SecurePDFEngineException(
            f"Engine failed to produce receipt. Stderr: {result.stderr}"
        )

    finally:
        Path(policy_path).unlink(missing_ok=True)
        Path(receipt_path).unlink(missing_ok=True)
