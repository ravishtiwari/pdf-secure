#!/usr/bin/env python3
"""SecurePDF Test CLI - Modular testing tool with lazy loading.

This CLI provides commands for testing encryption, provenance tracking,
foundation verification, and end-to-end workflows.

Commands are loaded lazily to minimize startup time and dependencies.
"""

import sys
from pathlib import Path

import typer

# Ensure test_lib is in path
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

app = typer.Typer(
    help="SecurePDF Test CLI - Modular testing tool for encryption, provenance, and verification.",
    add_completion=False,
    no_args_is_help=True,
)


@app.command()
def encryption(
    input_path: Path = typer.Option(
        ...,
        "--in",
        "-i",
        help="Path to input PDF file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_path: Path = typer.Option(
        ...,
        "--out",
        "-o",
        help="Path to output PDF file",
        writable=True,
    ),
    policy_path: Path = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to policy JSON file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    engine_bin: Path = typer.Option(
        Path("bin/securepdf-engine"),
        "--engine-bin",
        "-b",
        help="Path to securepdf-engine binary",
    ),
    engine_opts: list[str] = typer.Option(
        None,
        "--engine-opt",
        "-e",
        help="Engine runtime options (key=value, repeatable)",
    ),
):
    """Test PDF encryption with the SecurePDF engine.

    Example:
        python test.py encryption --in doc.pdf --out secure.pdf --policy policy.json
    """
    # Lazy import
    from test_lib.commands.encryption import encryption_command

    encryption_command(input_path, output_path, policy_path, engine_bin, engine_opts)


@app.command()
def provenance(
    input_path: Path = typer.Option(
        ..., "--in", "-i", help="Path to input PDF", exists=True
    ),
    output_path: Path = typer.Option(..., "--out", "-o", help="Path to output PDF"),
    engine_bin: Path = typer.Option(
        Path("bin/securepdf-engine"),
        "--engine-bin",
        "-b",
        help="Path to engine binary",
    ),
    password: str = typer.Option("", "--password", help="Encryption password"),
    input_password: str = typer.Option(
        "", "--input-password", help="Input PDF password"
    ),
    document_id: str = typer.Option("auto", "--document-id", help="Document ID"),
    copy_id: str = typer.Option("auto", "--copy-id", help="Copy ID"),
    verify_metadata: bool = typer.Option(
        False, "--verify-metadata", help="Verify metadata"
    ),
    validate_only: bool = typer.Option(
        False, "--validate-only", help="Only validate metadata"
    ),
):
    """Test provenance tracking with document and copy IDs.

    Example:
        python test.py provenance --in doc.pdf --out tracked.pdf --verify-metadata
    """
    # Lazy import
    from test_lib.commands.provenance import provenance_command

    provenance_command(
        input_path,
        output_path,
        engine_bin,
        password,
        input_password,
        document_id,
        copy_id,
        verify_metadata,
        validate_only,
    )


@app.command(name="verify-foundation")
def verify_foundation():
    """Verify SecurePDF foundation setup.

    Checks for required directories, files, and module structure.

    Example:
        python test.py verify-foundation
    """
    # Lazy import
    from test_lib.commands.foundation import foundation_command

    foundation_command()


@app.command(name="e2e-encryption")
def e2e_encryption(
    input_path: Path = typer.Option(
        ...,
        "--in",
        "-i",
        help="Path to input PDF",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    password: str = typer.Option(..., "--password", "-pw", help="Encryption password"),
    engine_bin: Path = typer.Option(
        Path("bin/securepdf-engine"),
        "--engine-bin",
        "-b",
        help="Path to engine binary",
    ),
    test_tamper: bool = typer.Option(
        True, "--test-tamper/--skip-tamper", help="Test tamper detection"
    ),
    verify_metadata: bool = typer.Option(
        True, "--verify-metadata/--skip-metadata", help="Verify metadata"
    ),
    cleanup: bool = typer.Option(
        True, "--cleanup/--no-cleanup", help="Cleanup temp files"
    ),
):
    """Run end-to-end encryption and tamper detection test.

    Comprehensive test workflow:
    1. Encrypt PDF with password and provenance
    2. Verify encryption status
    3. Test tamper detection with wrong passwords
    4. Decrypt with correct password
    5. Verify metadata integrity

    Example:
        python test.py e2e-encryption --in doc.pdf --password secret123
    """
    # Lazy import
    from test_lib.commands.e2e import e2e_command

    e2e_command(input_path, password, engine_bin, test_tamper, verify_metadata, cleanup)


@app.callback()
def main():
    """SecurePDF Test CLI - Modular testing tool."""
    pass


if __name__ == "__main__":
    app()
