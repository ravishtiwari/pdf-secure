"""Engine utilities for SecurePDF Test CLI."""

import typer


def parse_engine_opts(opts: list[str]) -> dict[str, str]:
    """Parse engine options from key=value format.

    Args:
        opts: List of strings in "key=value" format

    Returns:
        Dictionary of parsed options

    Raises:
        typer.BadParameter: If option format is invalid
    """
    result = {}
    for opt in opts:
        if "=" not in opt:
            raise typer.BadParameter(
                f"Engine option must be in key=value format: {opt}"
            )
        key, value = opt.split("=", 1)
        result[key.strip()] = value.strip()
    return result
