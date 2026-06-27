"""Tests for SecurePDF Python SDK with V1 schema."""

import json

import pytest

from securepdf.exception import SecurePDFEngineException
from securepdf.models import (
    ERR_ENCRYPTION_FAILED,
    # Error codes
    ERR_POLICY_INVALID,
    WARN_VIEWER_DEPENDENT_ACK,
    # Warning codes
    WARN_WEAK_CRYPTO_REQUESTED,
    AckConfig,
    EncryptionConfig,
    InvisibleLabel,
    LabelsConfig,
    Policy,
    ProvenanceConfig,
    Receipt,
    ReceiptError,
    ReceiptWarning,
    TamperDetectionConfig,
    VisibleLabel,
)
from securepdf.sdk import secure_pdf


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

    def test_secure_pdf_timeout_derived_from_engine_opts(self, monkeypatch, tmp_path):
        """Test that subprocess timeout derives from engine_opts['timeout_ms']."""
        import subprocess as sp

        import securepdf.sdk as sdk_mod

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            raise sp.TimeoutExpired(cmd, kwargs.get("timeout"))

        monkeypatch.setattr(sdk_mod.subprocess, "run", fake_run)
        engine = tmp_path / "fake-engine"
        engine.write_text("#!/bin/sh\n")
        engine.chmod(0o755)

        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                "dummy.pdf",
                "out.pdf",
                policy,
                engine_bin=str(engine),
                engine_opts={"timeout_ms": "5000"},
            )
        assert captured["timeout"] == 5.0
        assert "5.0 seconds" in str(exc_info.value)


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


class TestPolicyValidation:
    """Tests for Policy.validate() method."""

    def test_policy_validate_catches_missing_password(self):
        """Test that validate() catches missing password."""
        policy = Policy(
            policy_version="1.0",
            encryption=EncryptionConfig(enabled=True, user_password=""),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("password" in err.lower() for err in errors)

    def test_policy_validate_accepts_valid(self):
        """Test that validate() accepts valid policy."""
        policy = Policy(
            policy_version="1.0",
            encryption=EncryptionConfig(enabled=True, user_password="secret123"),
        )
        valid, errors = policy.validate()
        assert valid, f"Policy should be valid, got errors: {errors}"
        assert len(errors) == 0

    def test_policy_validate_catches_invalid_version(self):
        """Test that validate() catches invalid version."""
        policy = Policy(
            policy_version="2.0",  # Unsupported
            encryption=EncryptionConfig(enabled=False),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("version" in err.lower() for err in errors)


# ---------------------------------------------------------------------------
# Additional tests added to raise coverage to ≥70%
# ---------------------------------------------------------------------------


class TestFindEngineBin:
    """Tests for _find_engine_bin helper."""

    def test_find_engine_bin_falls_back_to_path_name(self):
        """When no bundled binary exists, returns a Path with just the binary name."""
        from securepdf.sdk import _find_engine_bin

        result = _find_engine_bin()
        # On non-Windows it should resolve to "securepdf-engine"
        assert result.name == "securepdf-engine"

    def test_find_engine_bin_returns_bundled_when_exists(self, tmp_path, monkeypatch):
        """When bundled binary exists in package bin/, it is returned."""
        import securepdf.sdk as sdk_mod

        # Monkeypatch __file__ of sdk module to point at tmp_path
        fake_pkg = tmp_path / "securepdf"
        fake_bin = fake_pkg / "bin"
        fake_bin.mkdir(parents=True)
        bundled = fake_bin / "securepdf-engine"
        bundled.write_text("#!/bin/sh\n")
        bundled.chmod(0o755)

        monkeypatch.setattr(sdk_mod, "__file__", str(fake_pkg / "sdk.py"))
        result = sdk_mod._find_engine_bin()
        assert result == bundled


class TestSecurePdfSuccessPath:
    """Tests for secure_pdf success and typed-failure paths via mocked subprocess."""

    def _make_receipt_json(self, ok=True, error_code=None, error_msg=None):
        data = {
            "ok": ok,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": [],
            "error": (
                {"code": error_code, "message": error_msg or ""} if error_code else None
            ),
            "document_id": "doc-abc",
            "copy_id": "copy-xyz",
        }
        return json.dumps(data)

    def _make_fake_run(self, monkeypatch, tmp_path, returncode=0, receipt_json=None):
        """Return a fake subprocess.run that writes a receipt file."""
        import subprocess as sp

        import securepdf.sdk as sdk_mod

        def fake_run(cmd, **kwargs):
            # Find receipt path from cmd args (--receipt <path>)
            receipt_path = None
            for i, arg in enumerate(cmd):
                if str(arg) == "--receipt" and i + 1 < len(cmd):
                    receipt_path = cmd[i + 1]
                    break
            if receipt_path and receipt_json is not None:
                import pathlib

                pathlib.Path(receipt_path).write_text(receipt_json, encoding="utf-8")
            return sp.CompletedProcess(cmd, returncode=returncode, stdout="", stderr="")

        monkeypatch.setattr(sdk_mod.subprocess, "run", fake_run)

        engine = tmp_path / "fake-engine"
        engine.write_text("#!/bin/sh\n")
        engine.chmod(0o755)
        return engine

    def test_success_returns_receipt(self, monkeypatch, tmp_path):
        """secure_pdf returns a Receipt when engine returns 0 and valid receipt."""
        receipt_json = self._make_receipt_json(ok=True)
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=0, receipt_json=receipt_json
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        result = secure_pdf(
            str(tmp_path / "in.pdf"),
            str(tmp_path / "out.pdf"),
            policy,
            engine_bin=str(engine),
        )
        assert result.ok is True
        assert result.document_id == "doc-abc"
        assert result.copy_id == "copy-xyz"

    def test_failure_e001_raises_policy_invalid(self, monkeypatch, tmp_path):
        """secure_pdf raises SecurePDFPolicyInvalidError for E001."""
        from securepdf.exception import SecurePDFPolicyInvalidError

        receipt_json = self._make_receipt_json(
            ok=False, error_code="E001", error_msg="Policy is invalid"
        )
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=2, receipt_json=receipt_json
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFPolicyInvalidError):
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )

    def test_failure_e003_raises_input_unsupported(self, monkeypatch, tmp_path):
        """secure_pdf raises SecurePDFInputUnsupportedError for E003."""
        from securepdf.exception import SecurePDFInputUnsupportedError

        receipt_json = self._make_receipt_json(
            ok=False, error_code="E003", error_msg="Unsupported feature"
        )
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=3, receipt_json=receipt_json
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFInputUnsupportedError):
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )

    def test_nonzero_returncode_no_receipt_raises_engine_exception(
        self, monkeypatch, tmp_path
    ):
        """When returncode != 0 and no receipt file, raises SecurePDFEngineException."""
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=1, receipt_json=None
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )
        assert "Engine exited with code 1" in str(exc_info.value)

    def test_zero_returncode_no_receipt_raises_engine_exception(
        self, monkeypatch, tmp_path
    ):
        """When returncode == 0 but no receipt produced, raises SecurePDFEngineException."""
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=0, receipt_json=None
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )
        assert "failed to produce receipt" in str(exc_info.value).lower()

    def test_oserror_raises_engine_exception(self, monkeypatch, tmp_path):
        """OSError from subprocess.run is wrapped in SecurePDFEngineException."""
        import securepdf.sdk as sdk_mod

        def fake_run_oserr(cmd, **kwargs):
            raise OSError("Permission denied")

        monkeypatch.setattr(sdk_mod.subprocess, "run", fake_run_oserr)
        engine = tmp_path / "fake-engine"
        engine.write_text("#!/bin/sh\n")
        engine.chmod(0o755)

        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )
        assert "Failed to execute engine binary" in str(exc_info.value)

    def test_receipt_with_ok_false_no_error_details(self, monkeypatch, tmp_path):
        """receipt.ok=False with no error field raises generic SecurePDFException."""
        from securepdf.exception import SecurePDFException

        data = {
            "ok": False,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": [],
            "error": None,
        }
        receipt_json = json.dumps(data)
        engine = self._make_fake_run(
            monkeypatch, tmp_path, returncode=1, receipt_json=receipt_json
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFException):
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )

    def test_corrupt_receipt_json_falls_through_to_returncode_error(
        self, monkeypatch, tmp_path
    ):
        """Corrupt receipt JSON causes fall-through to returncode error path."""
        import securepdf.sdk as sdk_mod

        def fake_run(cmd, **kwargs):
            import pathlib
            import subprocess as sp

            for i, arg in enumerate(cmd):
                if str(arg) == "--receipt" and i + 1 < len(cmd):
                    pathlib.Path(cmd[i + 1]).write_text(
                        "{{invalid json", encoding="utf-8"
                    )
                    break
            return sp.CompletedProcess(
                cmd, returncode=1, stdout="", stderr="engine error"
            )

        monkeypatch.setattr(sdk_mod.subprocess, "run", fake_run)
        engine = tmp_path / "fake-engine"
        engine.write_text("#!/bin/sh\n")
        engine.chmod(0o755)

        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFEngineException) as exc_info:
            secure_pdf(
                str(tmp_path / "in.pdf"),
                str(tmp_path / "out.pdf"),
                policy,
                engine_bin=str(engine),
            )
        assert "Engine exited with code 1" in str(exc_info.value)


class TestBatchSecurePdf:
    """Tests for batch_secure_pdf function."""

    def _patch_secure_pdf(self, monkeypatch, receipts_iter):
        """Patch sdk.secure_pdf to return receipts from an iterator."""
        import securepdf.sdk as sdk_mod

        receipts = list(receipts_iter)
        call_count = {"n": 0}

        def fake_secure_pdf(*args, **kwargs):
            idx = call_count["n"]
            call_count["n"] += 1
            r = receipts[idx]
            if isinstance(r, Exception):
                raise r
            return r

        monkeypatch.setattr(sdk_mod, "secure_pdf", fake_secure_pdf)

    def _ok_receipt(self):
        return Receipt(
            ok=True,
            engine_version="0.0.1",
            policy_version="1.0",
            warnings=[],
        )

    def test_batch_success_two_pdfs(self, monkeypatch):
        """batch_secure_pdf returns two receipts on success."""
        from securepdf.sdk import batch_secure_pdf

        self._patch_secure_pdf(monkeypatch, [self._ok_receipt(), self._ok_receipt()])
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        results = batch_secure_pdf(
            [("in1.pdf", "out1.pdf"), ("in2.pdf", "out2.pdf")],
            policy,
            max_workers=2,
        )
        assert len(results) == 2
        assert all(r.ok for r in results)

    def test_batch_failure_raises_secure_pdf_exception(self, monkeypatch):
        """batch_secure_pdf re-raises as SecurePDFException when one PDF fails."""
        from securepdf.exception import SecurePDFException
        from securepdf.sdk import batch_secure_pdf

        self._patch_secure_pdf(
            monkeypatch,
            [SecurePDFEngineException("engine failed"), self._ok_receipt()],
        )
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        with pytest.raises(SecurePDFException) as exc_info:
            batch_secure_pdf(
                [("in1.pdf", "out1.pdf"), ("in2.pdf", "out2.pdf")],
                policy,
                max_workers=2,
            )
        assert "Failed to process" in str(exc_info.value)

    def test_batch_with_engine_binary_path(self, monkeypatch, tmp_path):
        """batch_secure_pdf passes engine_binary_path to process_one."""
        import securepdf.sdk as sdk_mod
        from securepdf.sdk import batch_secure_pdf

        captured = {}

        def fake_secure_pdf(
            input_path, output_path, policy, engine_bin=None, engine_opts=None
        ):
            captured["engine_bin"] = engine_bin
            return self._ok_receipt()

        monkeypatch.setattr(sdk_mod, "secure_pdf", fake_secure_pdf)

        engine = tmp_path / "my-engine"
        policy = Policy(encryption=EncryptionConfig(user_password="test"))
        batch_secure_pdf(
            [("in.pdf", "out.pdf")],
            policy,
            engine_binary_path=str(engine),
            max_workers=1,
        )
        assert captured["engine_bin"] == engine


class TestExceptionFromReceipt:
    """Tests for exception_from_receipt mapping."""

    def _make_receipt(self, error_code, error_msg="some error"):
        return Receipt(
            ok=False,
            engine_version="0.0.1",
            policy_version="1.0",
            warnings=[],
            error=ReceiptError(code=error_code, message=error_msg),
        )

    def test_returns_none_for_ok_receipt(self):
        from securepdf.exception import exception_from_receipt

        r = Receipt(ok=True, engine_version="0.0.1", policy_version="1.0", warnings=[])
        assert exception_from_receipt(r) is None

    @pytest.mark.parametrize(
        "code, exc_cls_name",
        [
            ("E001", "SecurePDFPolicyInvalidError"),
            ("E002", "SecurePDFInputInvalidError"),
            ("E003", "SecurePDFInputUnsupportedError"),
            ("E004", "SecurePDFEncryptionError"),
            ("E005", "SecurePDFLabelError"),
            ("E006", "SecurePDFProvenanceError"),
            ("E007", "SecurePDFTamperHashError"),
            ("E008", "SecurePDFOutputError"),
            ("E009", "SecurePDFTimeoutError"),
            ("E010", "SecurePDFMemoryLimitError"),
            ("E011", "SecurePDFInputReadError"),
            ("E012", "SecurePDFWeakCryptoRejectedError"),
            ("E099", "SecurePDFInternalError"),
        ],
    )
    def test_maps_error_codes_to_exception_classes(self, code, exc_cls_name):
        from securepdf.exception import exception_from_receipt

        receipt = self._make_receipt(code)
        exc = exception_from_receipt(receipt)
        assert type(exc).__name__ == exc_cls_name
        assert exc.receipt is receipt

    def test_unknown_code_maps_to_base_exception(self):
        from securepdf.exception import SecurePDFException, exception_from_receipt

        receipt = self._make_receipt("E999")
        exc = exception_from_receipt(receipt)
        assert type(exc) is SecurePDFException


class TestReceiptToDict:
    """Tests for Receipt.to_dict method."""

    def test_to_dict_success_minimal(self):
        r = Receipt(ok=True, engine_version="1.0", policy_version="1.0", warnings=[])
        d = r.to_dict()
        assert d["ok"] is True
        assert d["warnings"] == []
        assert "error" not in d

    def test_to_dict_with_error_and_details(self):
        r = Receipt(
            ok=False,
            engine_version="1.0",
            policy_version="1.0",
            warnings=[],
            error=ReceiptError(code="E001", message="bad", details={"field": "x"}),
        )
        d = r.to_dict()
        assert d["error"]["code"] == "E001"
        assert d["error"]["details"] == {"field": "x"}

    def test_to_dict_with_optional_fields(self):
        r = Receipt(
            ok=True,
            engine_version="1.0",
            policy_version="1.0",
            warnings=[],
            document_id="did",
            copy_id="cid",
            input_sha256="sha:in",
            output_sha256="sha:out",
            input_content_hash="sha:content",
            timestamp="2024-01-01T00:00:00Z",
        )
        d = r.to_dict()
        assert d["document_id"] == "did"
        assert d["copy_id"] == "cid"
        assert d["input_sha256"] == "sha:in"
        assert d["output_sha256"] == "sha:out"
        assert d["input_content_hash"] == "sha:content"
        assert d["timestamp"] == "2024-01-01T00:00:00Z"

    def test_from_dict_legacy_warning_string(self):
        """Legacy warnings as plain strings get code UNKNOWN."""
        data = {
            "ok": True,
            "engine_version": "0.0.1",
            "policy_version": "1.0",
            "warnings": ["plain string warning"],
            "error": None,
        }
        r = Receipt.from_dict(data)
        assert r.warnings[0].code == "UNKNOWN"
        assert r.warnings[0].message == "plain string warning"

    def test_to_dict_error_without_details(self):
        r = Receipt(
            ok=False,
            engine_version="1.0",
            policy_version="1.0",
            warnings=[],
            error=ReceiptError(code="E004", message="enc failed"),
        )
        d = r.to_dict()
        assert "details" not in d["error"]


class TestPolicyFromDict:
    """Tests for Policy.from_dict and sub-config from_dict methods."""

    def test_policy_from_dict_full(self):
        data = {
            "policy_version": "1.0",
            "encryption": {
                "enabled": True,
                "mode": "password",
                "user_password": "abc",
                "allow_print": True,
                "allow_copy": False,
                "allow_modify": False,
                "crypto_profile": "compat",
            },
            "ack": {"required": True, "text": "OSS_DEFAULT"},
            "labels": {
                "mode": "visible",
                "visible": {"text": "TOP SECRET", "placement": "header"},
                "invisible": {"enabled": True, "namespace": "com.test"},
            },
            "provenance": {"enabled": True, "document_id": "auto", "copy_id": "auto"},
            "tamper_detection": {"enabled": True},
        }
        policy = Policy.from_dict(data)
        assert policy.policy_version == "1.0"
        assert policy.encryption.user_password == "abc"
        assert policy.ack.required is True
        assert policy.labels.mode == "visible"
        assert policy.labels.visible.text == "TOP SECRET"
        assert policy.labels.invisible.namespace == "com.test"
        assert policy.provenance.enabled is True
        assert policy.tamper_detection.enabled is True

    def test_policy_from_dict_minimal(self):
        data = {"policy_version": "1.0"}
        policy = Policy.from_dict(data)
        assert policy.encryption.enabled is True  # default
        assert policy.ack is None

    def test_policy_validate_invalid_crypto_profile(self):
        from securepdf.models.policy import EncryptionConfig as EC

        policy = Policy(
            policy_version="1.0",
            encryption=EC(enabled=True, user_password="pw", crypto_profile="quantum"),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("crypto_profile" in e for e in errors)

    def test_policy_validate_invalid_labels_mode(self):
        from securepdf.models.policy import LabelsConfig, VisibleLabel

        policy = Policy(
            policy_version="1.0",
            encryption=EncryptionConfig(enabled=False),
            labels=LabelsConfig(mode="visible", visible=VisibleLabel(text="")),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("text" in e for e in errors)

    def test_policy_validate_invisible_disabled(self):
        from securepdf.models.policy import InvisibleLabel, LabelsConfig

        policy = Policy(
            policy_version="1.0",
            encryption=EncryptionConfig(enabled=False),
            labels=LabelsConfig(
                mode="invisible",
                invisible=InvisibleLabel(enabled=False),
            ),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("invisible" in e for e in errors)

    def test_policy_validate_tamper_detection_invalid_profile(self):
        from securepdf.models.policy import TamperDetectionConfig

        policy = Policy(
            policy_version="1.0",
            encryption=EncryptionConfig(enabled=False),
            tamper_detection=TamperDetectionConfig(
                enabled=True, hash_profile="bad_profile"
            ),
        )
        valid, errors = policy.validate()
        assert not valid
        assert any("hash_profile" in e for e in errors)
