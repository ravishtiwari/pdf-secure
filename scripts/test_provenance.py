import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PYTHON_DIR = REPO_ROOT / "python"
sys.path.append(str(PYTHON_DIR))

from securepdf import Policy, secure_pdf  # noqa: E402
from securepdf.models import (  # noqa: E402
    EncryptionConfig,
    ProvenanceConfig,
)


def _load_pypdf():
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        return None
    return PdfReader


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecurePDF provenance test helper (engine + SDK).",
    )
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument(
        "--engine-bin",
        default=str(REPO_ROOT / "bin" / "securepdf-engine"),
    )
    parser.add_argument("--password", default="", help="Encrypt output if set.")
    parser.add_argument(
        "--input-password",
        default="",
        help="Password for encrypted input PDFs (requires pypdf).",
    )
    parser.add_argument("--document-id", default="auto")
    parser.add_argument("--copy-id", default="auto")
    parser.add_argument(
        "--verify-metadata",
        action="store_true",
        help="Verify provenance in PDF metadata (requires pypdf).",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Skip engine processing; only validate existing PDF metadata.",
    )

    args = parser.parse_args()

    input_path = Path(args.input_path)
    if not input_path.exists():
        raise RuntimeError(f"Input file not found: {input_path}")

    if args.validate_only:
        if not args.verify_metadata:
            raise RuntimeError("--validate-only requires --verify-metadata.")
        meta = _read_metadata(input_path, args.input_password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")
        print("Metadata Document ID:", doc_val)
        print("Metadata Copy ID:", copy_val)
        return 0

    if args.input_password:
        input_path = _decrypt_to_temp(input_path, args.input_password)
    elif _is_encrypted(input_path):
        raise RuntimeError(
            "Input PDF is encrypted; provide --input-password to decrypt."
        )

    encrypt = bool(args.password)
    enc = EncryptionConfig(
        enabled=encrypt,
        mode="password",
        user_password=args.password,
    )
    prov = ProvenanceConfig(
        enabled=True,
        document_id=args.document_id,
        copy_id=args.copy_id,
    )

    policy = Policy(
        encryption=enc,
        provenance=prov,
    )

    receipt = secure_pdf(
        input_path=str(input_path),
        output_path=args.output_path,
        policy=policy,
        engine_bin=args.engine_bin,
    )

    print("OK:", receipt.ok)
    print("Document ID:", receipt.document_id)
    print("Copy ID:", receipt.copy_id)
    print("Output SHA256:", receipt.output_sha256)

    if args.verify_metadata:
        meta = _read_metadata(Path(args.output_path), args.password or None)
        doc_key = "/SecurePDF_DocumentID"
        copy_key = "/SecurePDF_CopyID"
        doc_val = meta.get(doc_key, "")
        copy_val = meta.get(copy_key, "")

        print("Metadata Document ID:", doc_val)
        print("Metadata Copy ID:", copy_val)

        if receipt.document_id and receipt.document_id != doc_val:
            raise SystemExit("document_id mismatch between receipt and metadata")
        if receipt.copy_id and receipt.copy_id != copy_val:
            raise SystemExit("copy_id mismatch between receipt and metadata")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
