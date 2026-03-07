"""Shared utilities for SecurePDF test commands."""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def parse_engine_opts(opts: list[str]) -> dict[str, str]:
    """Parse engine options from key=value format.

    Args:
        opts: List of key=value strings

    Returns:
        Dictionary of parsed options

    Raises:
        ValueError: If option format is invalid
    """
    result = {}
    for opt in opts:
        if "=" not in opt:
            raise ValueError(f"Engine option must be in key=value format: {opt}")
        key, value = opt.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def load_pypdf():
    """Lazy load pypdf if available.

    Returns:
        PdfReader class or None if not available
    """
    try:
        from pypdf import PdfReader

        return PdfReader
    except ImportError:
        return None


def is_encrypted(path: Path) -> bool:
    """Check if a PDF is encrypted.

    Args:
        path: Path to PDF file

    Returns:
        True if PDF is encrypted, False otherwise
    """
    reader_cls = load_pypdf()
    if reader_cls is None:
        return False
    reader = reader_cls(str(path))
    return bool(reader.is_encrypted)


def read_metadata(path: Path, password: Optional[str] = None) -> dict[str, str]:
    """Read PDF metadata using pypdf or qpdf fallback.

    Args:
        path: Path to PDF file
        password: Password for encrypted PDFs

    Returns:
        Dictionary of metadata key-value pairs

    Raises:
        RuntimeError: If PDF cannot be read
    """
    reader_cls = load_pypdf()
    if reader_cls is None:
        return _read_metadata_qpdf(path, password)

    reader = reader_cls(str(path))
    if reader.is_encrypted:
        if not password:
            raise RuntimeError("PDF is encrypted; provide password for metadata read.")
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


def _read_metadata_qpdf(path: Path, password: Optional[str]) -> dict[str, str]:
    """Read metadata using qpdf command-line tool.

    Args:
        path: Path to PDF file
        password: Password for encrypted PDFs

    Returns:
        Dictionary of metadata

    Raises:
        RuntimeError: If qpdf fails
    """
    qpdf = shutil.which("qpdf")
    if qpdf is None:
        raise RuntimeError("qpdf not found in PATH and pypdf is unavailable.")

    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-meta-"))
    out_path = temp_dir / "input.qdf"

    cmd = [qpdf]
    if password:
        cmd.append(f"--password={password}")
    cmd.extend(
        [
            "--qdf",
            "--object-streams=disable",
            "--stream-data=uncompress",
            str(path),
            str(out_path),
        ]
    )

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"qpdf failed: {result.stderr.strip() or result.stdout.strip()}"
        )

    text = out_path.read_text(errors="ignore")
    meta = {}
    for key in ("SecurePDF_DocumentID", "SecurePDF_CopyID"):
        m = re.search(rf"/{key}\s*\\(([^)]*)\\)", text)
        if m:
            meta[f"/{key}"] = m.group(1)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)
    return meta


def decrypt_to_temp(path: Path, password: str) -> Path:
    """Decrypt PDF to temporary file.

    Args:
        path: Path to encrypted PDF
        password: Decryption password

    Returns:
        Path to decrypted temporary PDF

    Raises:
        RuntimeError: If decryption fails
    """
    if shutil.which("qpdf") is not None:
        return _decrypt_with_qpdf(path, password)

    reader_cls = load_pypdf()
    if reader_cls is None:
        raise RuntimeError(
            "pypdf is not installed. Install with: python -m pip install pypdf"
        )

    reader = reader_cls(str(path))
    if not reader.is_encrypted:
        return path

    if not password:
        raise RuntimeError("Input PDF is encrypted; provide password to decrypt.")

    reader.decrypt(password)
    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-decrypt-"))
    out_path = temp_dir / "decrypted.pdf"

    from pypdf import PdfWriter

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with out_path.open("wb") as f:
        writer.write(f)

    return out_path


def _decrypt_with_qpdf(path: Path, password: str) -> Path:
    """Decrypt PDF using qpdf.

    Args:
        path: Path to encrypted PDF
        password: Decryption password

    Returns:
        Path to decrypted PDF

    Raises:
        RuntimeError: If qpdf fails
    """
    qpdf = shutil.which("qpdf")
    if qpdf is None:
        raise RuntimeError("qpdf not found in PATH.")

    temp_dir = Path(tempfile.mkdtemp(prefix="securepdf-decrypt-"))
    out_path = temp_dir / "decrypted.pdf"

    result = subprocess.run(
        [qpdf, f"--password={password}", "--decrypt", str(path), str(out_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"qpdf failed: {result.stderr.strip() or result.stdout.strip()}"
        )

    return out_path
