import json
import subprocess
import tempfile
from contextlib import ExitStack
from pathlib import Path
from beartype import beartype
from beartype.typing import Optional, Union
from .models import Policy, Receipt
from .exception import SecurePDFEngineException

PathLike = Union[str, Path]


@beartype
def secure_pdf(
    input_path: PathLike,
    output_path: PathLike,
    policy: Policy,
    engine_bin: PathLike = Path("securepdf-engine"),
    engine_opts: Optional[dict[str, str]] = None,
) -> Receipt:
    """Secures a PDF using the Go engine.

    Args:
        input_path: Path to the input PDF file.
        output_path: Path where the secured PDF will be written.
        policy: Policy defining the security settings.
        engine_bin: Path to the securepdf-engine binary.
        engine_opts: Engine runtime options as key=value pairs.
            Supported options:
            - reject_weak_crypto: "true" or "false" (reject weak crypto profiles)
            - timeout_ms: Timeout in milliseconds (e.g., "60000")
            - max_input_mb: Maximum input file size in MB (e.g., "200")
            - max_memory_mb: Maximum memory usage in MB (e.g., "512")

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

        # Add engine options
        if engine_opts:
            for key, value in engine_opts.items():
                cmd.extend(["--engine-opt", f"{key}={value}"])

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
