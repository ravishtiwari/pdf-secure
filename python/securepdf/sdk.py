import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path

from beartype import beartype
from beartype.typing import List, Optional, Tuple, Union

from .exception import (
    SecurePDFEngineException,
    SecurePDFException,
    exception_from_receipt,
)
from .models import Policy, Receipt

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
    # Resolve to absolute paths to prevent path traversal via symlinks or ../
    input_path = Path(input_path).resolve()
    output_path = Path(output_path).resolve()

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

        # Write directly to the open handle to avoid reopening the file — eliminates
        # the TOCTOU window between write and chmod. NamedTemporaryFile already
        # creates files at 0o600 on POSIX, so no explicit chmod is needed.
        policy_file.write(policy.to_json())
        policy_file.flush()

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
            # TODO: needs fix - derive timeout from engine_opts["timeout_ms"] if provided instead of hardcoding 600s
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError as e:
            raise SecurePDFEngineException(
                f"Engine binary not found: {engine_bin}\n"
                f"Please ensure the securepdf-engine binary is installed and in your PATH,\n"
                f"or specify the path with --engine-bin or engine_bin parameter."
            ) from e
        except subprocess.TimeoutExpired:
            raise SecurePDFEngineException(
                "Engine execution timed out after 600 seconds.\n"
                "Consider using engine option timeout_ms to adjust processing timeout."
            )
        except OSError as e:
            raise SecurePDFEngineException(
                f"Failed to execute engine binary: {e}\n"
                f"Please check file permissions and ensure the binary is executable."
            ) from e

        # Always try to read receipt first — engine writes it even on failure.
        # This allows typed exceptions to be raised based on the error code.
        receipt: Optional[Receipt] = None
        if receipt_path.exists():
            try:
                data = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt = Receipt.from_dict(data)
            except (json.JSONDecodeError, Exception):
                pass  # Fall through to generic error below

        if receipt is not None and not receipt.ok:
            exc = exception_from_receipt(receipt)
            if exc:
                raise exc

        if result.returncode != 0:
            stderr = result.stderr.strip() if result.stderr else "No error output"
            raise SecurePDFEngineException(
                f"Engine exited with code {result.returncode}.\n"
                f"Error output: {stderr}\n"
                f"Check the receipt file for detailed error information."
            )

        if receipt is None:
            stderr = result.stderr.strip() if result.stderr else "No error output"
            raise SecurePDFEngineException(
                f"Engine failed to produce receipt.\n"
                f"Error output: {stderr}\n"
                f"This usually indicates a critical engine failure."
            )

        return receipt


@beartype
def batch_secure_pdf(
    pdf_pairs: List[Tuple[str, str]],
    policy: Policy,
    engine_binary_path: str | None = None,
    engine_options: dict | None = None,
    max_workers: int = 4,
) -> List[Receipt]:
    """
    Process multiple PDFs in parallel using a shared policy.

    Args:
        pdf_pairs: List of (input_path, output_path) tuples
        policy: Policy to apply to all PDFs
        engine_binary_path: Optional path to engine binary
        engine_options: Optional engine options dict
        max_workers: Maximum number of parallel workers (default: 4)

    Returns:
        List of Receipt objects (one per input PDF, in same order as input)

    Raises:
        SecurePDFException: If any PDF processing fails

    Examples:
        >>> pairs = [("in1.pdf", "out1.pdf"), ("in2.pdf", "out2.pdf")]
        >>> policy = Policy(policy_version="1.0", encryption=EncryptionConfig(enabled=False))
        >>> receipts = batch_secure_pdf(pairs, policy)
        >>> assert len(receipts) == 2
    """

    @beartype
    def process_one(input_path: str, output_path: str) -> Receipt:
        """Process a single PDF."""
        engine_bin = (
            Path(engine_binary_path) if engine_binary_path else Path("securepdf-engine")
        )
        return secure_pdf(
            input_path,
            output_path,
            policy,
            engine_bin=engine_bin,
            engine_opts=engine_options,
        )

    receipts = [None] * len(pdf_pairs)  # Preserve order

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks with index to preserve order
        future_to_index = {
            executor.submit(process_one, inp, out): i
            for i, (inp, out) in enumerate(pdf_pairs)
        }

        # Collect results as they complete
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                receipt = future.result()
                receipts[index] = receipt
            except Exception as e:
                # Re-raise with context about which file failed
                input_path, output_path = pdf_pairs[index]
                raise SecurePDFException(f"Failed to process {input_path}: {e}") from e

    return receipts
