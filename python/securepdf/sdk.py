import json
import subprocess
import tempfile
from contextlib import ExitStack
from pathlib import Path
from .helpers.data_class import Policy, Receipt
from .exception import SecurePDFEngineException


def secure_pdf(
    input_path: Path,
    output_path: Path,
    policy: Policy,
    engine_bin: Path = Path("securepdf-engine"),
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
    with ExitStack() as stack:
        policy_file = stack.enter_context(
            tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        )
        receipt_file = stack.enter_context(
            tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        )

        policy_path = Path(policy_file.name)
        receipt_path = Path(receipt_file.name)

        stack.callback(lambda: policy_path.unlink(missing_ok=True))
        stack.callback(lambda: receipt_path.unlink(missing_ok=True))

        policy_path.write_text(policy.to_json(), encoding="utf-8")
        policy_path.chmod(0o600)
        receipt_path.chmod(0o600)

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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError as e:
            raise SecurePDFEngineException(
                f"Engine binary not found: {engine_bin}"
            ) from e
        except OSError as e:
            raise SecurePDFEngineException(
                f"Failed to execute engine binary: {e}"
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
