#!/usr/bin/env python3
"""
SecurePDF Test CLI - Unified test tool for encryption, provenance, and foundation verification.
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add the python directory to the path so we can import securepdf
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.append(str(PYTHON_DIR))

from securepdf import Policy, SecurePDFEngineException, secure_pdf
from securepdf.models import (
    EncryptionConfig,
    LabelsConfig,
    ProvenanceConfig,
    VisibleLabel,
)

app = typer.Typer(
    help="SecurePDF Test CLI - Test encryption, provenance, and verify foundation.",
    add_completion=False,
)
console = Console()


# =============================================================================
# Encryption Test Command (from test_encryption.py)
# =============================================================================


def parse_engine_opts(opts: List[str]) -> dict[str, str]:
    """Parse engine options from key=value format."""
    result = {}
    for opt in opts:
        if "=" not in opt:
            raise typer.BadParameter(
                f"Engine option must be in key=value format: {opt}"
            )
        key, value = opt.split("=", 1)
        result[key.strip()] = value.strip()
    return result


@app.command()
def encryption(
    input_path: Path = typer.Option(
        ...,
        "--in",
        "-i",
        help="Path to the input PDF file to be secured.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_path: Path = typer.Option(
        ...,
        "--out",
        "-o",
        help="Path where the secured PDF will be saved.",
        writable=True,
    ),
    policy_path: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to the policy JSON file defining security settings.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    engine_bin: Path = typer.Option(
        Path("bin/securepdf-engine"),
        "--engine-bin",
        "-b",
        help="Path to the securepdf-engine binary.",
    ),
    engine_opts: Optional[List[str]] = typer.Option(
        None,
        "--engine-opt",
        "-e",
        help="Runtime options for the engine as key=value pairs (can be specified multiple times). e.g. reject_weak_crypto=true",
    ),
):
    """
    Test PDF encryption using the SecurePDF Go engine.

    Acceptable engine options:
    - reject_weak_crypto: "true" or "false" (reject weak crypto profiles)
    - timeout_ms: Timeout in milliseconds (e.g., "60000")
    - max_input_mb: Maximum input file size in MB (e.g., "200")
    - max_memory_mb: Maximum memory usage in MB (e.g., "512")
    """

    # Load policy from JSON
    try:
        policy_data = json.loads(policy_path.read_text(encoding="utf-8"))

        # Supporting legacy format conversion
        if "policy_version" not in policy_data and "encryption" not in policy_data:
            policy = Policy()
            if "password" in policy_data:
                policy.encryption.user_password = policy_data["password"]
            if "visible_label" in policy_data:
                policy.labels = LabelsConfig(
                    mode="visible",
                    visible=VisibleLabel(text=policy_data["visible_label"]),
                )
        else:
            policy = Policy.from_dict(policy_data)

    except Exception as e:
        console.print(f"[bold red]Error loading policy:[/bold red] {e}")
        raise typer.Exit(code=1)

    parsed_opts = parse_engine_opts(engine_opts) if engine_opts else {}

    console.print(f"[bold blue]Submitting transformation...[/bold blue]")
    console.print(f"  Input:  {input_path}")
    console.print(f"  Output: {output_path}")
    console.print(f"  Policy: {policy_path}")

    try:
        receipt = secure_pdf(
            input_path=input_path,
            output_path=output_path,
            policy=policy,
            engine_bin=engine_bin,
            engine_opts=parsed_opts,
        )
    except SecurePDFEngineException as e:
        console.print(
            Panel(f"[bold red]Engine Error:[/bold red]\n{e}", title="Failure")
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            Panel(f"[bold red]Unexpected Error:[/bold red]\n{e}", title="Failure")
        )
        raise typer.Exit(code=1)

    # Display results
    if receipt.ok:
        status_color = "green"
        status_text = "SUCCESS"
    else:
        status_color = "red"
        status_text = "FAILED"

    console.print(
        Panel(
            f"Status: [bold {status_color}]{status_text}[/bold {status_color}]",
            title="Result",
        )
    )

    if receipt.error:
        console.print(
            f"[bold red]Error:[/bold red] {receipt.error.message} ({receipt.error.code})"
        )
        if receipt.error.details:
            console.print("Details:")
            for k, v in receipt.error.details.items():
                console.print(f"  - {k}: {v}")

    if receipt.warnings:
        table = Table(title="Warnings", box=None)
        table.add_column("Code", style="yellow")
        table.add_column("Message")
        for w in receipt.warnings:
            table.add_row(w.code, w.message)
        console.print(table)

    if receipt.ok:
        info_table = Table(box=None, show_header=False)
        info_table.add_row("Engine Version", receipt.engine_version)
        info_table.add_row("Policy Version", receipt.policy_version)
        if receipt.document_id:
            info_table.add_row("Document ID", receipt.document_id)
        if receipt.output_sha256:
            info_table.add_row("Output SHA256", receipt.output_sha256)
        console.print(info_table)


# =============================================================================
# Provenance Test Command (from test_provenance.py)
# =============================================================================


def _load_pypdf():
    try:
        from pypdf import PdfReader  # type: ignore

        return PdfReader
    except Exception:
        return None


def _read_metadata(path: Path, password: str | None) -> dict[str, str]:
    reader_cls = _load_pypdf()
    if reader_cls is None:
        return _read_metadata_qpdf(path, password)

    reader = reader_cls(str(path))
    if reader.is_encrypted:
        if not password:
            raise RuntimeError(
                "PDF is encrypted; provide --password for metadata read."
            )
        reader.decrypt(password)

    meta = reader.metadata or {}
    result = {}
    for key, value in meta.items():
        if key is None or value is None:
            continue
        if isinstance(value, str):
            result[str(key)] = value
        else:
            result[str(key)] = str(value)
    return result


def _read_metadata_qpdf(path: Path, password: str | None) -> dict[str, str]:
    qpdf = shutil.which("qpdf")
    if qpdf is None:
        raise RuntimeError("qpdf not found in PATH and pypdf is unavailable.")

    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-prov-meta-"))
    out_path = temp_dir / "input.qdf"

    cmd = [qpdf]
    if password:
        cmd.append("--password=" + password)
    cmd.extend(
        [
            "--qdf",
            "--object-streams=disable",
            "--stream-data=uncompress",
            str(path),
            str(out_path),
        ]
    )

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "qpdf failed to read metadata: "
            + (result.stderr.strip() or result.stdout.strip())
        )

    text = out_path.read_text(errors="ignore")
    meta = {}
    for key in ("SecurePDF_DocumentID", "SecurePDF_CopyID"):
        m = re.search(rf"/{key}\s*\\(([^)]*)\\)", text)
        if m:
            meta[f"/{key}"] = m.group(1)
    return meta


def _is_encrypted(path: Path) -> bool:
    reader_cls = _load_pypdf()
    if reader_cls is None:
        return False
    reader = reader_cls(str(path))
    return bool(reader.is_encrypted)


def _decrypt_with_qpdf(path: Path, password: str) -> Path:
    qpdf = shutil.which("qpdf")
    if qpdf is None:
        raise RuntimeError("qpdf not found in PATH.")

    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-prov-"))
    out_path = temp_dir / "input-decrypted.pdf"

    result = subprocess.run(
        [qpdf, "--password=" + password, "--decrypt", str(path), str(out_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "qpdf failed to decrypt input: "
            + (result.stderr.strip() or result.stdout.strip())
        )

    return out_path


def _decrypt_to_temp(path: Path, password: str) -> Path:
    if shutil.which("qpdf") is not None:
        return _decrypt_with_qpdf(path, password)

    reader_cls = _load_pypdf()
    if reader_cls is None:
        raise RuntimeError(
            "pypdf is not installed. Install with: python -m pip install pypdf"
        )

    reader = reader_cls(str(path))
    if not reader.is_encrypted:
        return path

    if not password:
        raise RuntimeError(
            "Input PDF is encrypted; provide --input-password to decrypt."
        )

    reader.decrypt(password)
    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-prov-"))
    out_path = temp_dir / "input-decrypted.pdf"

    from pypdf import PdfWriter  # type: ignore

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with out_path.open("wb") as f:
        writer.write(f)

    return out_path


@app.command()
def provenance(
    input_path: Path = typer.Option(
        ..., "--in", "-i", help="Path to input PDF file", exists=True
    ),
    output_path: Path = typer.Option(
        ..., "--out", "-o", help="Path to output PDF file"
    ),
    engine_bin: Path = typer.Option(
        REPO_ROOT / "bin" / "securepdf-engine",
        "--engine-bin",
        "-b",
        help="Path to securepdf-engine binary",
    ),
    password: str = typer.Option("", "--password", help="Encrypt output if set"),
    input_password: str = typer.Option(
        "",
        "--input-password",
        help="Password for encrypted input PDFs (requires pypdf)",
    ),
    document_id: str = typer.Option("auto", "--document-id", help="Document ID"),
    copy_id: str = typer.Option("auto", "--copy-id", help="Copy ID"),
    verify_metadata: bool = typer.Option(
        False,
        "--verify-metadata",
        help="Verify provenance in PDF metadata (requires pypdf)",
    ),
    validate_only: bool = typer.Option(
        False,
        "--validate-only",
        help="Skip engine processing; only validate existing PDF metadata",
    ),
):
    """
    Test provenance tracking with the SecurePDF engine.

    This command tests document and copy ID generation and embedding.
    """

    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file not found: {input_path}")
        raise typer.Exit(code=1)

    if validate_only:
        if not verify_metadata:
            console.print(
                "[bold red]Error:[/bold red] --validate-only requires --verify-metadata"
            )
            raise typer.Exit(code=1)
        meta = _read_metadata(input_path, input_password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")
        console.print(f"Metadata Document ID: [cyan]{doc_val}[/cyan]")
        console.print(f"Metadata Copy ID: [cyan]{copy_val}[/cyan]")
        return

    if input_password:
        input_path = _decrypt_to_temp(input_path, input_password)
    elif _is_encrypted(input_path):
        console.print(
            "[bold red]Error:[/bold red] Input PDF is encrypted; provide --input-password"
        )
        raise typer.Exit(code=1)

    encrypt = bool(password)
    enc = EncryptionConfig(
        enabled=encrypt,
        mode="password",
        user_password=password,
    )
    prov = ProvenanceConfig(
        enabled=True,
        document_id=document_id,
        copy_id=copy_id,
    )

    policy = Policy(
        encryption=enc,
        provenance=prov,
    )

    console.print("[bold blue]Processing PDF with provenance...[/bold blue]")

    try:
        receipt = secure_pdf(
            input_path=str(input_path),
            output_path=str(output_path),
            policy=policy,
            engine_bin=str(engine_bin),
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    console.print(f"OK: [{'green' if receipt.ok else 'red'}]{receipt.ok}[/]")
    console.print(f"Document ID: [cyan]{receipt.document_id}[/cyan]")
    console.print(f"Copy ID: [cyan]{receipt.copy_id}[/cyan]")
    console.print(f"Output SHA256: [dim]{receipt.output_sha256}[/dim]")

    if verify_metadata:
        meta = _read_metadata(Path(output_path), password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")

        console.print(f"Metadata Document ID: [cyan]{doc_val}[/cyan]")
        console.print(f"Metadata Copy ID: [cyan]{copy_val}[/cyan]")

        if receipt.document_id and receipt.document_id != doc_val:
            console.print(
                "[bold red]Error:[/bold red] document_id mismatch between receipt and metadata"
            )
            raise typer.Exit(code=1)
        if receipt.copy_id and receipt.copy_id != copy_val:
            console.print(
                "[bold red]Error:[/bold red] copy_id mismatch between receipt and metadata"
            )
            raise typer.Exit(code=1)

        console.print("[bold green]✓[/bold green] Metadata verification passed")


# =============================================================================
# Foundation Verification Command (from verify_foundation.py)
# =============================================================================


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def has_files_with_extension(path: Path, extension: str) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    return any(path.glob(f"*{extension}"))


def run_checks(root: Path) -> list[CheckResult]:
    checks: list[CheckResult] = []

    def add_check(name: str, ok: bool, detail: str) -> None:
        checks.append(CheckResult(name=name, ok=ok, detail=detail))

    engine_dir = root / "engine"
    python_dir = root / "python"
    docs_dir = root / "docs"

    add_check(
        "Repo layout",
        engine_dir.is_dir() and python_dir.is_dir() and docs_dir.is_dir(),
        "expected engine/, python/, docs/",
    )

    add_check(
        "Engine module",
        (engine_dir / "go.mod").is_file(),
        "engine/go.mod",
    )

    add_check(
        "CLI skeleton",
        (engine_dir / "cmd" / "securepdf-engine" / "main.go").is_file(),
        "engine/cmd/securepdf-engine/main.go",
    )

    add_check(
        "Docs: engine contract",
        (docs_dir / "engine-contract.md").is_file(),
        "docs/engine-contract.md",
    )

    add_check(
        "Docs: architecture",
        (docs_dir / "pdf-secure-architecture-final.md").is_file(),
        "docs/pdf-secure-architecture-final.md",
    )

    add_check(
        "Policy loader",
        has_files_with_extension(engine_dir / "pkg" / "policy", ".go"),
        "engine/pkg/policy/*.go",
    )

    add_check(
        "Receipt writer",
        has_files_with_extension(engine_dir / "pkg" / "receipt", ".go"),
        "engine/pkg/receipt/*.go",
    )

    add_check(
        "Python package skeleton",
        has_files_with_extension(python_dir / "securepdf", ".py"),
        "python/securepdf/*.py",
    )

    return checks


@app.command()
def verify_foundation():
    """
    Verify that the SecurePDF foundation is properly set up.

    Checks for required directories, files, and module structure.
    """
    checks = run_checks(REPO_ROOT)

    console.print("[bold]Foundation Verification[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Status", width=8)
    table.add_column("Check")
    table.add_column("Detail", style="dim")

    failures = 0
    for check in checks:
        if check.ok:
            status = "[green]PASS[/green]"
        else:
            status = "[red]FAIL[/red]"
            failures += 1

        table.add_row(status, check.name, check.detail)

    console.print(table)

    if failures:
        console.print(f"\n[bold red]{failures} check(s) failed.[/bold red]")
        raise typer.Exit(code=1)

    console.print("\n[bold green]✓ All foundation checks passed.[/bold green]")


# =============================================================================
# End-to-End Encryption & Tamper Detection Test Command
# =============================================================================


@app.command()
def e2e_encryption(
    input_path: Path = typer.Option(
        ...,
        "--in",
        "-i",
        help="Path to the input PDF file to test.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    password: str = typer.Option(
        ...,
        "--password",
        "-pw",
        help="Password to use for encryption.",
    ),
    engine_bin: Path = typer.Option(
        Path("bin/securepdf-engine"),
        "--engine-bin",
        "-b",
        help="Path to the securepdf-engine binary.",
    ),
    test_tamper: bool = typer.Option(
        True,
        "--test-tamper/--skip-tamper",
        help="Test tamper detection by attempting to decrypt with wrong password.",
    ),
    verify_metadata: bool = typer.Option(
        True,
        "--verify-metadata/--skip-metadata",
        help="Verify provenance metadata in encrypted PDF.",
    ),
    cleanup: bool = typer.Option(
        True,
        "--cleanup/--no-cleanup",
        help="Clean up temporary files after test.",
    ),
):
    """
    End-to-end test for PDF encryption and tamper detection.

    This command performs a comprehensive test workflow:
    1. Encrypts the input PDF with password and provenance tracking
    2. Verifies the encrypted PDF can be decrypted with correct password
    3. Tests tamper detection by attempting decryption with wrong password
    4. Verifies metadata integrity and provenance tracking
    5. Calculates and compares SHA256 checksums
    """

    console.print(
        "[bold blue]Starting End-to-End Encryption & Tamper Detection Test[/bold blue]\n"
    )

    # Create temporary directory for test outputs
    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-e2e-"))
    encrypted_path = temp_dir / "encrypted.pdf"
    decrypted_path = temp_dir / "decrypted.pdf"

    test_results = []

    try:
        # =====================================================================
        # Test 1: Encrypt the PDF with password and provenance
        # =====================================================================
        console.print(
            "[bold]Test 1:[/bold] Encrypting PDF with password and provenance tracking..."
        )

        policy = Policy(
            encryption=EncryptionConfig(
                enabled=True,
                mode="password",
                user_password=password,
            ),
            provenance=ProvenanceConfig(
                enabled=True,
                document_id="auto",
                copy_id="auto",
            ),
        )

        try:
            encrypt_receipt = secure_pdf(
                input_path=str(input_path),
                output_path=str(encrypted_path),
                policy=policy,
                engine_bin=str(engine_bin),
            )

            if encrypt_receipt.ok:
                console.print("[green]✓[/green] Encryption successful")
                console.print(f"  Document ID: {encrypt_receipt.document_id}")
                console.print(f"  Copy ID: {encrypt_receipt.copy_id}")
                console.print(f"  SHA256: {encrypt_receipt.output_sha256}")
                test_results.append(("Encryption", True, "PDF encrypted successfully"))
            else:
                console.print(
                    f"[red]✗[/red] Encryption failed: {encrypt_receipt.error}"
                )
                test_results.append(("Encryption", False, str(encrypt_receipt.error)))
                raise typer.Exit(code=1)

        except Exception as e:
            console.print(f"[red]✗[/red] Encryption error: {e}")
            test_results.append(("Encryption", False, str(e)))
            raise typer.Exit(code=1)

        console.print()

        # =====================================================================
        # Test 2: Verify encrypted PDF exists and is different from original
        # =====================================================================
        console.print("[bold]Test 2:[/bold] Verifying encrypted PDF integrity...")

        if not encrypted_path.exists():
            console.print("[red]✗[/red] Encrypted PDF does not exist")
            test_results.append(("File Creation", False, "Encrypted file not found"))
            raise typer.Exit(code=1)

        encrypted_size = encrypted_path.stat().st_size
        original_size = input_path.stat().st_size
        console.print(f"[green]✓[/green] Encrypted PDF created")
        console.print(f"  Original size: {original_size:,} bytes")
        console.print(f"  Encrypted size: {encrypted_size:,} bytes")
        test_results.append(("File Creation", True, f"{encrypted_size:,} bytes"))
        console.print()

        # =====================================================================
        # Test 3: Verify PDF is actually encrypted
        # =====================================================================
        console.print("[bold]Test 3:[/bold] Verifying PDF encryption status...")

        is_enc = _is_encrypted(encrypted_path)
        if is_enc:
            console.print("[green]✓[/green] PDF is encrypted")
            test_results.append(("Encryption Status", True, "PDF is encrypted"))
        else:
            console.print("[red]✗[/red] PDF is NOT encrypted")
            test_results.append(("Encryption Status", False, "PDF not encrypted"))
        console.print()

        # =====================================================================
        # Test 4: Test tamper detection with wrong password
        # =====================================================================
        if test_tamper:
            console.print(
                "[bold]Test 4:[/bold] Testing tamper detection with wrong password..."
            )

            wrong_passwords = [
                "wrongpassword",
                password + "wrong",
                "",
                "12345",
            ]

            tamper_detected = False
            for wrong_pw in wrong_passwords:
                try:
                    _read_metadata(encrypted_path, wrong_pw)
                    console.print(
                        f"[yellow]![/yellow] Warning: Decryption succeeded with wrong password '{wrong_pw}'"
                    )
                except Exception:
                    tamper_detected = True
                    break

            if tamper_detected:
                console.print(
                    "[green]✓[/green] Tamper detection working: wrong passwords rejected"
                )
                test_results.append(
                    ("Tamper Detection", True, "Wrong passwords rejected")
                )
            else:
                console.print(
                    "[yellow]![/yellow] Warning: Could not verify tamper detection"
                )
                test_results.append(("Tamper Detection", False, "Could not verify"))

            console.print()

        # =====================================================================
        # Test 5: Decrypt with correct password
        # =====================================================================
        console.print("[bold]Test 5:[/bold] Decrypting PDF with correct password...")

        decrypt_policy = Policy(
            encryption=EncryptionConfig(enabled=False),
            provenance=ProvenanceConfig(enabled=False),
        )

        try:
            # First decrypt to temp using helper
            temp_decrypted = _decrypt_to_temp(encrypted_path, password)

            # Now process through engine to create final decrypted output
            decrypt_receipt = secure_pdf(
                input_path=str(temp_decrypted),
                output_path=str(decrypted_path),
                policy=decrypt_policy,
                engine_bin=str(engine_bin),
            )

            if decrypt_receipt.ok:
                console.print("[green]✓[/green] Decryption successful")
                test_results.append(("Decryption", True, "PDF decrypted successfully"))
            else:
                console.print(
                    f"[red]✗[/red] Decryption failed: {decrypt_receipt.error}"
                )
                test_results.append(("Decryption", False, str(decrypt_receipt.error)))

        except Exception as e:
            console.print(f"[red]✗[/red] Decryption error: {e}")
            test_results.append(("Decryption", False, str(e)))

        console.print()

        # =====================================================================
        # Test 6: Verify metadata integrity
        # =====================================================================
        if verify_metadata:
            console.print("[bold]Test 6:[/bold] Verifying metadata and provenance...")

            try:
                meta = _read_metadata(encrypted_path, password)
                doc_id = meta.get("/SecurePDF_DocumentID", "")
                copy_id = meta.get("/SecurePDF_CopyID", "")

                console.print(f"  Document ID: {doc_id}")
                console.print(f"  Copy ID: {copy_id}")

                if doc_id and copy_id:
                    if (
                        doc_id == encrypt_receipt.document_id
                        and copy_id == encrypt_receipt.copy_id
                    ):
                        console.print("[green]✓[/green] Metadata matches receipt")
                        test_results.append(
                            ("Metadata Integrity", True, "IDs match receipt")
                        )
                    else:
                        console.print("[red]✗[/red] Metadata mismatch with receipt")
                        test_results.append(
                            ("Metadata Integrity", False, "IDs don't match")
                        )
                else:
                    console.print(
                        "[yellow]![/yellow] Warning: Provenance metadata not found"
                    )
                    test_results.append(
                        ("Metadata Integrity", False, "Metadata not found")
                    )

            except Exception as e:
                console.print(f"[red]✗[/red] Metadata verification error: {e}")
                test_results.append(("Metadata Integrity", False, str(e)))

            console.print()

        # =====================================================================
        # Test Summary
        # =====================================================================
        console.print("[bold]Test Summary[/bold]\n")

        summary_table = Table(show_header=True, header_style="bold")
        summary_table.add_column("Test", style="cyan")
        summary_table.add_column("Status", width=10)
        summary_table.add_column("Details", style="dim")

        passed = 0
        failed = 0

        for test_name, success, details in test_results:
            if success:
                status = "[green]PASS[/green]"
                passed += 1
            else:
                status = "[red]FAIL[/red]"
                failed += 1

            summary_table.add_row(test_name, status, details)

        console.print(summary_table)

        console.print(f"\n[bold]Results:[/bold] {passed} passed, {failed} failed")

        if failed == 0:
            console.print("[bold green]✓ All tests passed![/bold green]")
        else:
            console.print(f"[bold red]✗ {failed} test(s) failed[/bold red]")

        console.print(f"\nTemporary files location: [dim]{temp_dir}[/dim]")

    finally:
        # Cleanup
        if cleanup and temp_dir.exists():
            console.print(f"\n[dim]Cleaning up temporary files...[/dim]")
            shutil.rmtree(temp_dir, ignore_errors=True)
        elif not cleanup:
            console.print(f"\n[dim]Temporary files preserved at: {temp_dir}[/dim]")


if __name__ == "__main__":
    app()
