"""E2E provenance tests for SecurePDF Python SDK."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from securepdf import Policy, secure_pdf
from securepdf.models import EncryptionConfig, ProvenanceConfig


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _engine_bin() -> Path:
    return _repo_root() / "bin" / "securepdf-engine"


def _sample_input() -> Path:
    return _repo_root() / "engine" / "test-pdfs" / "sample-input.pdf"


@pytest.mark.skipif(
    not _engine_bin().exists(),
    reason="securepdf-engine binary missing; build it before running this test",
)
def test_provenance_receipt_ids(tmp_path: Path) -> None:
    input_path = _sample_input()
    output_path = tmp_path / "out.pdf"

    policy = Policy(
        encryption=EncryptionConfig(enabled=False),
        provenance=ProvenanceConfig(enabled=True, document_id="auto", copy_id="auto"),
    )

    receipt = secure_pdf(
        input_path=input_path,
        output_path=output_path,
        policy=policy,
        engine_bin=_engine_bin(),
    )

    assert receipt.ok is True
    assert receipt.document_id
    assert receipt.copy_id

    doc_re = re.compile(
        r"^doc-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    copy_re = re.compile(
        r"^copy-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    assert doc_re.match(receipt.document_id)
    assert copy_re.match(receipt.copy_id)
