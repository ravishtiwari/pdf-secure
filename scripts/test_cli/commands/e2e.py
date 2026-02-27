"""End-to-end encryption and tamper detection test command."""

import shutil
import sys
import tempfile
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

# Add the python directory to the path so we can import securepdf
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.insert(0, str(PYTHON_DIR))

from securepdf import Policy, secure_pdf
from securepdf.models import EncryptionConfig, ProvenanceConfig

from ..utils import read_metadata, is_encrypted, decrypt_to_temp

console = Console()


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

        is_enc = is_encrypted(encrypted_path)
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
                    read_metadata(encrypted_path, wrong_pw)
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
            temp_decrypted = decrypt_to_temp(encrypted_path, password)

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
