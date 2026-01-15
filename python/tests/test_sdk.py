import json
import pytest
from securepdf.sdk import secure_pdf
from securepdf.helpers.data_class import Policy, Receipt
from securepdf.exception import SecurePDFEngineException


def test_policy_to_json():
    policy = Policy(password="test123", visible_label="Confidential")
    json_str = policy.to_json()
    data = json.loads(json_str)
    assert data["password"] == "test123"
    assert data["visible_label"] == "Confidential"
    assert data["encryption"] == "AES-256"  # default


def test_receipt_dataclass():
    receipt = Receipt(
        id="test-id",
        timestamp="2023-01-01T00:00:00Z",
        status="success",
        engine_version="1.0",
        errors=[],
        warnings=[],
    )
    assert receipt.id == "test-id"
    assert receipt.status == "success"


def test_secure_pdf_missing_engine():
    # Test error handling without actual engine
    policy = Policy(password="test")
    with pytest.raises(SecurePDFEngineException):
        secure_pdf("dummy.pdf", "out.pdf", policy, engine_bin="nonexistent-engine")
