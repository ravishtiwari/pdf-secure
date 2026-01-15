#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    checks = run_checks(root)

    print("Foundation verification")
    failures = 0

    for check in checks:
        status = "PASS" if check.ok else "FAIL"
        print(f"{status}: {check.name} ({check.detail})")
        if not check.ok:
            failures += 1

    if failures:
        print(f"\n{failures} check(s) failed.")
        return 1

    print("\nAll foundation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
