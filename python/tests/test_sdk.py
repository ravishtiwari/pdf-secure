"""Tests for SecurePDF Python SDK with V1 schema."""

import json
import pytest
from securepdf.helpers.data_class import (
    Policy,
    Receipt,
    ReceiptWarning,
    ReceiptError,
    EncryptionConfig,
    AckConfig,
    LabelsConfig,
    VisibleLabel,
    InvisibleLabel,
    ProvenanceConfig,
    TamperDetectionConfig,
    # Warning codes
    WARN_WEAK_CRYPTO_REQUESTED,
    WARN_VIEWER_DEPENDENT_ACK,
    # Error codes
    ERR_POLICY_INVALID,
    ERR_ENCRYPTION_FAILED,
)
from securepdf.sdk import secure_pdf
from securepdf.exception import SecurePDFEngineException


class TestPolicyDataclass:
    """Tests for Policy V1 dataclass."""

    def test_policy_defaults(self):
        """Test that Policy has correct defaults."""
        policy = Policy()
        assert policy.policy_version == "1.0"
        assert policy.encryption.enabled is True
        assert policy.encryption.mode == "password"
        assert policy.encryption.user_password == ""
        assert policy.encryption.crypto_profile == "strong"
        assert policy.ack is None
        assert policy.labels is None
        assert policy.provenance is None
        assert policy.tamper_detection is None

    def test_policy_with_encryption(self):
        """Test Policy with custom encryption config."""
        policy = Policy(
            encryption=EncryptionConfig(
                enabled=True,
                mode="password",
                user_password="test123",
                allow_print=True,
                crypto_profile="compat",
            )
        )
        json_str = policy.to_json()
        data = json.loads(json_str)

        assert data["policy_version"] == "1.0"
        assert data["encryption"]["enabled"] is True
        assert data["encryption"]["user_password"] == "test123"
        assert data["encryption"]["allow_print"] is True
        assert data["encryption"]["crypto_profile"] == "compat"

    def test_policy_with_all_features(self):
        """Test Policy with all optional features enabled."""
        policy = Policy(
            encryption=EncryptionConfig(
                enabled=True,
                user_password="secret",
            ),
            ack=AckConfig(required=True, text="OSS_DEFAULT"),
            labels=LabelsConfig(
                mode="visible",
                visible=VisibleLabel(text="CONFIDENTIAL", placement="footer"),
            ),
            provenance=ProvenanceConfig(enabled=True),
            tamper_detection=TamperDetectionConfig(enabled=True),
        )
        json_str = policy.to_json()
        data = json.loads(json_str)

        assert data["ack"]["required"] is True
        assert data["labels"]["mode"] == "visible"
        assert data["labels"]["visible"]["text"] == "CONFIDENTIAL"
        assert data["provenance"]["enabled"] is True
        assert data["tamper_detection"]["enabled"] is True

    def test_policy_to_json_omits_none_values(self):
        """Test that None values are omitted from JSON output."""
        policy = Policy()
        json_str = policy.to_json()
        data = json.loads(json_str)

        # Optional fields should not be present when None
        assert "ack" not in data
        assert "labels" not in data
        assert "provenance" not in data
        assert "tamper_detection" not in data

    def test_policy_visible_label_with_page_range(self):
        """Test visible label with page range configuration."""
        policy = Policy(
            labels=LabelsConfig(
                mode="visible",
                visible=VisibleLabel(
                    text="DRAFT",
                    pages="range",
                    page_range="1-5,10",
                ),
            )
        )
        json_str = policy.to_json()
        data = json.loads(json_str)

        assert data["labels"]["visible"]["pages"] == "range"
        assert data["labels"]["visible"]["page_range"] == "1-5,10"

    def test_policy_invisible_label_only(self):
        """Test invisible label configuration."""
        policy = Policy(
            labels=LabelsConfig(
                mode="invisible",
                invisible=InvisibleLabel(
                    enabled=True,
                    namespace="com.example.v1",
                ),
            )
        )
        json_str = policy.to_json()
        data = json.loads(json_str)

        assert data["labels"]["mode"] == "invisible"
        assert data["labels"]["invisible"]["namespace"] == "com.example.v1"


class TestReceiptDataclass:
    """Tests for Receipt V1 dataclass."""

    def test_receipt_success_basic(self):
        """Test Receipt with basic success fields."""
        receipt = Receipt(
            ok=True,
            engine_version="1.0.0",
            policy_version="1.0",
            warnings=[],
            error=None,
        )
        assert receipt.ok is True
        assert receipt.is_success is True
        assert receipt.engine_version == "1.0.0"
        assert receipt.policy_version == "1.0"
        assert receipt.has_warnings is False
        assert receipt.error is None

    def test_receipt_success_with_all_fields(self):
        """Test Receipt with all optional success fields."""
        receipt = Receipt(
            ok=True,
            engine_version="1.0.0",
            policy_version="1.0",
            warnings=[],
            error=None,
            document_id="doc-abc",
            copy_id="copy-xyz",
            input_sha256="sha256:abc123",
            output_sha256="sha256:def456",
            input_content_hash="sha256:content123",
            timestamp="2024-01-15T10:30:00Z",
        )
        assert receipt.document_id == "doc-abc"
        assert receipt.copy_id == "copy-xyz"
        assert receipt.input_sha256 == "sha256:abc123"
        assert receipt.output_sha256 == "sha256:def456"
        assert receipt.input_content_hash == "sha256:content123"

    def test_receipt_with_warnings(self):
        """Test Receipt with warnings."""
        receipt = Receipt(
            ok=True,
            engine_version="1.0.0",
            policy_version="1.0",
            warnings=[
                ReceiptWarning(code=WARN_WEAK_CRYPTO_REQUESTED, message="Weak crypto"),
                ReceiptWarning(
                    code=WARN_VIEWER_DEPENDENT_ACK, message="Viewer dependent"
                ),
            ],
        )
        assert receipt.ok is True
        assert receipt.has_warnings is True
        assert len(receipt.warnings) == 2
        assert receipt.warnings[0].code == WARN_WEAK_CRYPTO_REQUESTED

    def test_receipt_error(self):
        """Test Receipt with error."""
        receipt = Receipt(
            ok=False,
            engine_version="1.0.0",
            policy_version="1.0",
            warnings=[],
            error=ReceiptError(
                code=ERR_POLICY_INVALID,
                message="Policy is invalid",
                details={"field": "encryption.user_password"},
            ),
        )
        assert receipt.ok is False
        assert receipt.is_success is False
        assert receipt.error is not None
        assert receipt.get_error_code() == ERR_POLICY_INVALID
        assert receipt.get_error_message() == "Policy is invalid"
        assert receipt.error.details["field"] == "encryption.user_password"

    def test_receipt_from_dict_success(self):
        """Test Receipt.from_dict with success JSON."""
        data = {
            "ok": True,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": [],
            "error": None,
            "document_id": "doc-123",
            "copy_id": "copy-456",
        }
        receipt = Receipt.from_dict(data)
        assert receipt.ok is True
        assert receipt.engine_version == "0.0.1"
        assert receipt.document_id == "doc-123"

    def test_receipt_from_dict_with_warnings(self):
        """Test Receipt.from_dict with warnings."""
        data = {
            "ok": True,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": [
                {"code": "W001", "message": "Test warning"},
                {"code": "W003", "message": "Another warning"},
            ],
            "error": None,
        }
        receipt = Receipt.from_dict(data)
        assert len(receipt.warnings) == 2
        assert receipt.warnings[0].code == "W001"
        assert receipt.warnings[1].message == "Another warning"

    def test_receipt_from_dict_with_error(self):
        """Test Receipt.from_dict with error."""
        data = {
            "ok": False,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": [],
            "error": {
                "code": "E001",
                "message": "Policy invalid",
                "details": {"field": "encryption.mode"},
            },
        }
        receipt = Receipt.from_dict(data)
        assert receipt.ok is False
        assert receipt.error is not None
        assert receipt.error.code == "E001"
        assert receipt.error.details["field"] == "encryption.mode"


class TestSecurePdfFunction:
    """Tests for secure_pdf function."""

    def test_secure_pdf_missing_engine(self):
        """Test error handling when engine binary is not found."""
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin="nonexistent-engine-binary",
            )
        assert "Engine binary not found" in str(exc_info.value)

    def test_secure_pdf_with_engine_opts_missing_engine(self):
        """Test error handling with engine_opts when engine is not found."""
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin="nonexistent-engine-binary",
                engine_opts={"reject_weak_crypto": "true"},
            )
        assert "Engine binary not found" in str(exc_info.value)

    def test_secure_pdf_engine_opts_parameter_type(self):
        """Test that engine_opts accepts dict and is optional."""
        policy = Policy(encryption=EncryptionConfig(user_password="test"))

        # Test with None (default)
        with pytest.raises(SecurePDFEngineException):
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin="nonexistent-engine-binary",
                engine_opts=None,
            )

        # Test with empty dict
        with pytest.raises(SecurePDFEngineException):
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin="nonexistent-engine-binary",
                engine_opts={},
            )

        # Test with multiple options
        with pytest.raises(SecurePDFEngineException):
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin="nonexistent-engine-binary",
                engine_opts={
                    "reject_weak_crypto": "true",
                    "timeout_ms": "30000",
                    "max_input_mb": "100",
                },
            )


class TestEncryptionConfig:
    """Tests for EncryptionConfig dataclass."""

    def test_encryption_defaults(self):
        """Test EncryptionConfig default values."""
        config = EncryptionConfig()
        assert config.enabled is True
        assert config.mode == "password"
        assert config.user_password == ""
        assert config.allow_print is False
        assert config.allow_copy is False
        assert config.allow_modify is False
        assert config.crypto_profile == "strong"

    def test_encryption_custom_values(self):
        """Test EncryptionConfig with custom values."""
        config = EncryptionConfig(
            enabled=True,
            mode="password",
            user_password="secret123",
            allow_print=True,
            allow_copy=True,
            crypto_profile="legacy",
        )
        assert config.user_password == "secret123"
        assert config.allow_print is True
        assert config.allow_copy is True
        assert config.crypto_profile == "legacy"


class TestLabelsConfig:
    """Tests for label-related dataclasses."""

    def test_visible_label_defaults(self):
        """Test VisibleLabel default values."""
        label = VisibleLabel()
        assert label.text == ""
        assert label.placement == "footer"
        assert label.pages == "all"
        assert label.page_range is None

    def test_invisible_label_defaults(self):
        """Test InvisibleLabel default values."""
        label = InvisibleLabel()
        assert label.enabled is True
        assert label.namespace == "com.securepdf.v1"

    def test_labels_config_defaults(self):
        """Test LabelsConfig default values."""
        config = LabelsConfig()
        assert config.mode == "off"
        assert config.visible is None
        assert config.invisible is None


class TestWarningAndErrorCodes:
    """Tests for warning and error code constants."""

    def test_warning_codes_format(self):
        """Test that warning codes follow the W### format."""
        assert WARN_WEAK_CRYPTO_REQUESTED.startswith("W")
        assert WARN_VIEWER_DEPENDENT_ACK.startswith("W")

    def test_error_codes_format(self):
        """Test that error codes follow the E### format."""
        assert ERR_POLICY_INVALID.startswith("E")
        assert ERR_ENCRYPTION_FAILED.startswith("E")
