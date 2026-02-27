"""PDF utilities for reading metadata, checking encryption, and decryption."""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _load_pypdf():
    """Lazy load pypdf if available."""
    try:
        from pypdf import PdfReader  # type: ignore

        return PdfReader
    except Exception:
        return None


def read_metadata(path: Path, password: str | None) -> dict[str, str]:
    """Read PDF metadata, preferring pypdf but falling back to qpdf.

    Args:
        path: Path to PDF file
        password: Password for encrypted PDFs (optional)

    Returns:
        Dictionary of metadata key-value pairs

    Raises:
        RuntimeError: If PDF cannot be read or both pypdf and qpdf are unavailable
    """
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
    """Read PDF metadata using qpdf command-line tool.

    Args:
        path: Path to PDF file
        password: Password for encrypted PDFs (optional)

    Returns:
        Dictionary of metadata key-value pairs

    Raises:
        RuntimeError: If qpdf is not found or fails to read the PDF
    """
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
        m = re.search(rf"/{key}\\s*\\(([^)]*)\\)", text)
        if m:
            meta[f"/{key}"] = m.group(1)
    return meta


def is_encrypted(path: Path) -> bool:
    """Check if a PDF is encrypted.

    Args:
        path: Path to PDF file

    Returns:
        True if PDF is encrypted, False otherwise
    """
    reader_cls = _load_pypdf()
    if reader_cls is None:
        return False
    reader = reader_cls(str(path))
    return bool(reader.is_encrypted)


def decrypt_to_temp(path: Path, password: str) -> Path:
    """Decrypt a PDF to a temporary file.

    Args:
        path: Path to encrypted PDF
        password: Password for decryption

    Returns:
        Path to decrypted temporary file

    Raises:
        RuntimeError: If decryption fails or no decryption tool is available
    """
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


def _decrypt_with_qpdf(path: Path, password: str) -> Path:
    """Decrypt a PDF using qpdf command-line tool.

    Args:
        path: Path to encrypted PDF
        password: Password for decryption

    Returns:
        Path to decrypted temporary file

    Raises:
        RuntimeError: If qpdf is not found or decryption fails
    """
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
