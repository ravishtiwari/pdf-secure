"""Foundation verification command."""

from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass(frozen=True)
class CheckResult:
    """Result of a foundation check."""

    name: str
    ok: bool
    detail: str


def has_files_with_extension(path: Path, extension: str) -> bool:
    """Check if directory has files with given extension.

    Args:
        path: Directory to check
        extension: File extension (e.g., ".go")

    Returns:
        True if files with extension exist
    """
    if not path.exists() or not path.is_dir():
        return False
    return any(path.glob(f"*{extension}"))


def run_checks(root: Path) -> list[CheckResult]:
    """Run foundation verification checks.

    Args:
        root: Repository root directory

    Returns:
        List of check results
    """
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
        "Python package",
        has_files_with_extension(python_dir / "securepdf", ".py"),
        "python/securepdf/*.py",
    )

    return checks


def foundation_command():
    """Verify that the SecurePDF foundation is properly set up.

    Checks for required directories, files, and module structure.
    """
    # Find repo root
    script_dir = Path(__file__).resolve().parent.parent.parent
    repo_root = script_dir.parent

    checks = run_checks(repo_root)

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
