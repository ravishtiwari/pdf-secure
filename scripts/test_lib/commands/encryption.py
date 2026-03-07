"""Encryption test command."""

import json
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add parent directories to path
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.insert(0, str(PYTHON_DIR))

from securepdf import Policy, SecurePDFEngineException, secure_pdf
from securepdf.models import EncryptionConfig, LabelsConfig, VisibleLabel

from ..utils import parse_engine_opts

console = Console()


def encryption_command(
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
        help="Runtime options as key=value pairs (repeatable).",
    ),
):
    """Test PDF encryption using the SecurePDF Go engine.

    Engine options:
    - reject_weak_crypto: "true" or "false"
    - timeout_ms: Timeout in milliseconds
    - max_input_mb: Maximum input file size in MB
    - max_memory_mb: Maximum memory usage in MB
    """
    # Load policy
    try:
        policy_data = json.loads(policy_path.read_text(encoding="utf-8"))

        # Legacy format conversion
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

    console.print("[bold blue]Submitting transformation...[/bold blue]")
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
    status_color = "green" if receipt.ok else "red"
    status_text = "SUCCESS" if receipt.ok else "FAILED"

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
