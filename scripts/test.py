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


if __name__ == "__main__":
    app()
