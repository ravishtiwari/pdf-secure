import json
import subprocess
import tempfile
from pathlib import Path
from .helpers.data_class import Policy, Receipt
from .exception import SecurePDFEngineException


def secure_pdf(
    input_path: str,
    output_path: str,
    policy: Policy,
    engine_bin: str = "securepdf-engine",
) -> Receipt:
    """Secures a PDF using the Go engine.

    Args:
        input_path: Path to the input PDF file.
        output_path: Path where the secured PDF will be written.
        policy: Policy defining the security settings.
        engine_bin: Path to the securepdf-engine binary.

    Returns:
        Receipt with transformation result and metadata.

    Raises:
        SecurePDFEngineException: If the engine binary is not found or fails.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        policy_path = tmpdir_path / "policy.json"
        receipt_path = tmpdir_path / "receipt.json"

        policy_path.write_text(policy.to_json(), encoding="utf-8")

        cmd = [
            engine_bin,
            "secure",
            "--in",
            input_path,
            "--out",
            output_path,
            "--policy",
            str(policy_path),
            "--receipt",
            str(receipt_path),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError as e:
            raise SecurePDFEngineException(
                f"Engine binary not found: {engine_bin}"
            ) from e

        if result.returncode != 0:
            raise SecurePDFEngineException(
                "Engine exited with code "
                f"{result.returncode}. Stderr: {result.stderr.strip()}"
            )

        if not receipt_path.exists():
            raise SecurePDFEngineException(
                f"Engine failed to produce receipt. Stderr: {result.stderr.strip()}"
            )

        try:
            data = json.loads(receipt_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SecurePDFEngineException(
                "Engine produced invalid receipt JSON"
            ) from exc

        return Receipt.from_dict(data)
