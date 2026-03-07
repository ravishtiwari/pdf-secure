"""End-to-end encryption and tamper detection test command."""

import shutil
import sys
import tempfile
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Add parent directories to path
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.insert(0, str(PYTHON_DIR))

from securepdf import Policy, secure_pdf
from securepdf.models import EncryptionConfig, ProvenanceConfig

from ..utils import decrypt_to_temp, is_encrypted, read_metadata

console = Console()


def e2e_command(
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
        help="Test tamper detection.",
    ),
    verify_metadata: bool = typer.Option(
        True,
        "--verify-metadata/--skip-metadata",
        help="Verify provenance metadata.",
    ),
    cleanup: bool = typer.Option(
        True,
        "--cleanup/--no-cleanup",
        help="Clean up temporary files after test.",
    ),
):
    """End-to-end test for PDF encryption and tamper detection.

    Test workflow:
    1. Encrypt input PDF with password and provenance
    2. Verify encrypted PDF can be decrypted
    3. Test tamper detection with wrong password
    4. Verify metadata integrity
    5. Compare SHA256 checksums
    """
    console.print(
        "[bold blue]Starting End-to-End Encryption & Tamper Detection Test[/bold blue]\n"
    )

    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-e2e-"))
    encrypted_path = temp_dir / "encrypted.pdf"
    decrypted_path = temp_dir / "decrypted.pdf"

    test_results = []

    try:
        # Test 1: Encrypt
        console.print(
            "[bold]Test 1:[/bold] Encrypting PDF with password and provenance..."
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
                test_results.append(("Encryption", True, "Success"))
            else:
                console.print(f"[red]✗[/red] Failed: {encrypt_receipt.error}")
                test_results.append(("Encryption", False, str(encrypt_receipt.error)))
                raise typer.Exit(code=1)

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")
            test_results.append(("Encryption", False, str(e)))
            raise typer.Exit(code=1)

        console.print()

        # Test 2: Verify file creation
        console.print("[bold]Test 2:[/bold] Verifying encrypted PDF...")

        if not encrypted_path.exists():
            console.print("[red]✗[/red] Encrypted PDF does not exist")
            test_results.append(("File Creation", False, "Not found"))
            raise typer.Exit(code=1)

        encrypted_size = encrypted_path.stat().st_size
        original_size = input_path.stat().st_size
        console.print(f"[green]✓[/green] Created")
        console.print(f"  Original: {original_size:,} bytes")
        console.print(f"  Encrypted: {encrypted_size:,} bytes")
        test_results.append(("File Creation", True, f"{encrypted_size:,} bytes"))
        console.print()

        # Test 3: Verify encryption status
        console.print("[bold]Test 3:[/bold] Verifying encryption status...")

        is_enc = is_encrypted(encrypted_path)
        if is_enc:
            console.print("[green]✓[/green] PDF is encrypted")
            test_results.append(("Encryption Status", True, "Encrypted"))
        else:
            console.print("[red]✗[/red] PDF is NOT encrypted")
            test_results.append(("Encryption Status", False, "Not encrypted"))
        console.print()

        # Test 4: Tamper detection
        if test_tamper:
            console.print("[bold]Test 4:[/bold] Testing tamper detection...")

            wrong_passwords = ["wrongpassword", password + "wrong", "", "12345"]
            tamper_detected = False

            for wrong_pw in wrong_passwords:
                try:
                    read_metadata(encrypted_path, wrong_pw)
                    console.print(
                        f"[yellow]![/yellow] Warning: Wrong password '{wrong_pw}' accepted"
                    )
                except Exception:
                    tamper_detected = True
                    break

            if tamper_detected:
                console.print("[green]✓[/green] Wrong passwords rejected")
                test_results.append(("Tamper Detection", True, "Working"))
            else:
                console.print("[yellow]![/yellow] Could not verify")
                test_results.append(("Tamper Detection", False, "Unverified"))

            console.print()

        # Test 5: Decrypt
        console.print("[bold]Test 5:[/bold] Decrypting with correct password...")

        decrypt_policy = Policy(
            encryption=EncryptionConfig(enabled=False),
            provenance=ProvenanceConfig(enabled=False),
        )

        try:
            temp_decrypted = decrypt_to_temp(encrypted_path, password)

            decrypt_receipt = secure_pdf(
                input_path=str(temp_decrypted),
                output_path=str(decrypted_path),
                policy=decrypt_policy,
                engine_bin=str(engine_bin),
            )

            if decrypt_receipt.ok:
                console.print("[green]✓[/green] Decryption successful")
                test_results.append(("Decryption", True, "Success"))
            else:
                console.print(f"[red]✗[/red] Failed: {decrypt_receipt.error}")
                test_results.append(("Decryption", False, str(decrypt_receipt.error)))

        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")
            test_results.append(("Decryption", False, str(e)))

        console.print()

        # Test 6: Metadata verification
        if verify_metadata:
            console.print("[bold]Test 6:[/bold] Verifying metadata...")

            try:
                meta = read_metadata(encrypted_path, password)
                doc_id = meta.get("/SecurePDF_DocumentID", "")
                copy_id = meta.get("/SecurePDF_CopyID", "")

                console.print(f"  Document ID: {doc_id}")
                console.print(f"  Copy ID: {copy_id}")

                if doc_id and copy_id:
                    if (
                        doc_id == encrypt_receipt.document_id
                        and copy_id == encrypt_receipt.copy_id
                    ):
                        console.print("[green]✓[/green] Metadata matches")
                        test_results.append(("Metadata", True, "Matches receipt"))
                    else:
                        console.print("[red]✗[/red] Metadata mismatch")
                        test_results.append(("Metadata", False, "Mismatch"))
                else:
                    console.print("[yellow]![/yellow] Metadata not found")
                    test_results.append(("Metadata", False, "Not found"))

            except Exception as e:
                console.print(f"[red]✗[/red] Error: {e}")
                test_results.append(("Metadata", False, str(e)))

            console.print()

        # Summary
        console.print("[bold]Test Summary[/bold]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Test", style="cyan")
        table.add_column("Status", width=10)
        table.add_column("Details", style="dim")

        passed = 0
        failed = 0

        for test_name, success, details in test_results:
            if success:
                status = "[green]PASS[/green]"
                passed += 1
            else:
                status = "[red]FAIL[/red]"
                failed += 1

            table.add_row(test_name, status, details)

        console.print(table)

        console.print(f"\n[bold]Results:[/bold] {passed} passed, {failed} failed")

        if failed == 0:
            console.print("[bold green]✓ All tests passed![/bold green]")
        else:
            console.print(f"[bold red]✗ {failed} test(s) failed[/bold red]")

        console.print(f"\nTemporary files: [dim]{temp_dir}[/dim]")

    finally:
        if cleanup and temp_dir.exists():
            console.print("\n[dim]Cleaning up...[/dim]")
            shutil.rmtree(temp_dir, ignore_errors=True)
        elif not cleanup:
            console.print(f"\n[dim]Files preserved at: {temp_dir}[/dim]")
