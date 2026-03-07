"""Provenance test command."""

import sys
from pathlib import Path

import typer
from rich.console import Console

# Add parent directories to path
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.insert(0, str(PYTHON_DIR))

from securepdf import Policy, secure_pdf
from securepdf.models import EncryptionConfig, ProvenanceConfig

from ..utils import decrypt_to_temp, is_encrypted, read_metadata

console = Console()


def provenance_command(
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
        help="Password for encrypted input PDFs",
    ),
    document_id: str = typer.Option("auto", "--document-id", help="Document ID"),
    copy_id: str = typer.Option("auto", "--copy-id", help="Copy ID"),
    verify_metadata: bool = typer.Option(
        False,
        "--verify-metadata",
        help="Verify provenance in PDF metadata",
    ),
    validate_only: bool = typer.Option(
        False,
        "--validate-only",
        help="Skip processing; only validate existing metadata",
    ),
):
    """Test provenance tracking with the SecurePDF engine."""
    if not input_path.exists():
        console.print(f"[bold red]Error:[/bold red] Input file not found: {input_path}")
        raise typer.Exit(code=1)

    if validate_only:
        if not verify_metadata:
            console.print(
                "[bold red]Error:[/bold red] --validate-only requires --verify-metadata"
            )
            raise typer.Exit(code=1)
        meta = read_metadata(input_path, input_password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")
        console.print(f"Metadata Document ID: [cyan]{doc_val}[/cyan]")
        console.print(f"Metadata Copy ID: [cyan]{copy_val}[/cyan]")
        return

    if input_password:
        input_path = decrypt_to_temp(input_path, input_password)
    elif is_encrypted(input_path):
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
        meta = read_metadata(Path(output_path), password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")

        console.print(f"Metadata Document ID: [cyan]{doc_val}[/cyan]")
        console.print(f"Metadata Copy ID: [cyan]{copy_val}[/cyan]")

        if receipt.document_id and receipt.document_id != doc_val:
            console.print("[bold red]Error:[/bold red] document_id mismatch")
            raise typer.Exit(code=1)
        if receipt.copy_id and receipt.copy_id != copy_val:
            console.print("[bold red]Error:[/bold red] copy_id mismatch")
            raise typer.Exit(code=1)

        console.print("[bold green]✓[/bold green] Metadata verification passed")
