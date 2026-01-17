"""Data classes for SecurePDF V1 schema.

These dataclasses match the Go engine's policy and receipt schemas
as defined in engine-contract.md.
"""

import json
from dataclasses import dataclass, asdict, field
from typing import List, Optional


# =============================================================================
# Policy Schema (V1)
# =============================================================================


@dataclass
class EncryptionConfig:
    """Encryption settings for the secured PDF."""

    enabled: bool = True
    mode: str = "password"  # "password" only in V1
    user_password: str = ""
    allow_print: bool = False
    allow_copy: bool = False
    allow_modify: bool = False
    crypto_profile: str = "strong"  # "strong"|"compat"|"legacy"


@dataclass
class AckConfig:
    """Custodianship acknowledgment settings."""

    required: bool = True
    text: str = "OSS_DEFAULT"  # "OSS_DEFAULT" in V1
    viewer_dependent: bool = True


@dataclass
class VisibleLabel:
    """Settings for visible watermark/label overlays."""

    text: str = ""
    placement: str = "footer"  # "footer"|"header"
    pages: str = "all"  # "all"|"first"|"range"
    page_range: Optional[str] = None  # e.g., "1-3,8,10-12"


@dataclass
class InvisibleLabel:
    """Settings for invisible metadata markers."""

    enabled: bool = True
    namespace: str = "com.securepdf.v1"


@dataclass
class LabelsConfig:
    """Visible and invisible label settings."""

    mode: str = "off"  # "visible"|"invisible"|"off"
    visible: Optional[VisibleLabel] = None
    invisible: Optional[InvisibleLabel] = None


@dataclass
class ProvenanceConfig:
    """Document provenance tracking settings."""

    enabled: bool = True
    document_id: str = "auto"  # "auto" or custom string
    copy_id: str = "auto"  # "auto" or custom string


@dataclass
class TamperDetectionConfig:
    """Tamper detection settings."""

    enabled: bool = True
    hash_alg: str = "sha256"  # "sha256" only in V1


@dataclass
class Policy:
    """Policy defining transformation and security rules for a PDF (V1 schema).

    This matches the engine-contract.md specification.
    """

    policy_version: str = "1.0"
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    ack: Optional[AckConfig] = None
    labels: Optional[LabelsConfig] = None
    provenance: Optional[ProvenanceConfig] = None
    tamper_detection: Optional[TamperDetectionConfig] = None

    def to_json(self) -> str:
        """Serialize policy to JSON string for engine consumption."""

        def dict_factory(items):
            """Custom dict factory to handle nested dataclasses and None values."""
            result = {}
            for key, value in items:
                if value is None:
                    continue  # Skip None values
                if hasattr(value, "__dataclass_fields__"):
                    result[key] = asdict(value)
                else:
                    result[key] = value
            return result

        return json.dumps(asdict(self, dict_factory=dict_factory), indent=2)


# =============================================================================
# Receipt Schema (V1) - Full V1 contract with ok field and structured errors/warnings
# =============================================================================


@dataclass
class ReceiptWarning:
    """A non-fatal warning from the transformation process."""

    code: str  # Warning code (e.g., "W001")
    message: str  # Human-readable message


@dataclass
class ReceiptError:
    """A fatal error that prevented transformation."""

    code: str  # Error code (e.g., "E001")
    message: str  # Human-readable summary
    details: Optional[dict] = (
        None  # Additional context (e.g., {"field": "encryption.user_password"})
    )


@dataclass
class Receipt:
    """Receipt from a SecurePDF transformation (V1 schema).

    This matches the engine-contract.md specification.
    The receipt indicates success (ok=True) or failure (ok=False) with
    structured warnings and error information.
    """

    # Required fields (always present)
    ok: bool  # True if transformation succeeded
    engine_version: str  # Engine version (e.g., "0.0.1")
    policy_version: str  # Policy version used (e.g., "1.0")
    warnings: List[ReceiptWarning] = field(default_factory=list)  # Non-fatal issues
    error: Optional[ReceiptError] = None  # Fatal error (None if ok=True)

    # Identification fields (present on success)
    document_id: Optional[str] = None  # Provenance document ID
    copy_id: Optional[str] = None  # Provenance copy ID

    # Hash fields (present on success)
    input_sha256: Optional[str] = None  # SHA-256 of input file
    output_sha256: Optional[str] = None  # SHA-256 of output file
    input_content_hash: Optional[str] = None  # Tamper detection hash

    # Metadata
    timestamp: Optional[str] = None  # When transformation occurred

    @classmethod
    def from_dict(cls, data: dict) -> "Receipt":
        """Create a Receipt from a dictionary (e.g., from JSON).

        Handles nested warning and error structures.
        """
        warnings = []
        for w in data.get("warnings", []):
            if isinstance(w, dict):
                warnings.append(
                    ReceiptWarning(code=w.get("code", ""), message=w.get("message", ""))
                )
            else:
                # Legacy format support (plain strings)
                warnings.append(ReceiptWarning(code="UNKNOWN", message=str(w)))

        error = None
        error_data = data.get("error")
        if error_data and isinstance(error_data, dict):
            error = ReceiptError(
                code=error_data.get("code", ""),
                message=error_data.get("message", ""),
                details=error_data.get("details"),
            )

        return cls(
            ok=data.get("ok", False),
            engine_version=data.get("engine_version", ""),
            policy_version=data.get("policy_version", ""),
            warnings=warnings,
            error=error,
            document_id=data.get("document_id"),
            copy_id=data.get("copy_id"),
            input_sha256=data.get("input_sha256"),
            output_sha256=data.get("output_sha256"),
            input_content_hash=data.get("input_content_hash"),
            timestamp=data.get("timestamp"),
        )

    @property
    def is_success(self) -> bool:
        """Check if the transformation was successful."""
        return self.ok

    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0

    def get_error_code(self) -> Optional[str]:
        """Get the error code if present."""
        return self.error.code if self.error else None

    def get_error_message(self) -> Optional[str]:
        """Get the error message if present."""
        return self.error.message if self.error else None


# =============================================================================
# Warning and Error Code Constants (matching Go engine)
# =============================================================================

# Warning codes
WARN_WEAK_CRYPTO_REQUESTED = "W001"
WARN_WEAK_CRYPTO_REJECTED = "W002"
WARN_VIEWER_DEPENDENT_ACK = "W003"
WARN_UNSUPPORTED_PDF_FEATURE = "W004"
WARN_LABEL_PARTIALLY_APPLIED = "W005"
WARN_PROVENANCE_PARTIALLY_APPLIED = "W006"
WARN_TAMPER_HASH_EMBED_FAILED = "W007"
WARN_UNKNOWN_POLICY_FIELD = "W008"

# Error codes
ERR_POLICY_INVALID = "E001"
ERR_INPUT_PDF_INVALID = "E002"
ERR_INPUT_PDF_UNSUPPORTED = "E003"
ERR_ENCRYPTION_FAILED = "E004"
ERR_LABEL_FAILED = "E005"
ERR_PROVENANCE_FAILED = "E006"
ERR_TAMPER_HASH_FAILED = "E007"
ERR_OUTPUT_WRITE_FAILED = "E008"
ERR_RUNTIME_TIMEOUT = "E009"
ERR_RUNTIME_MEMORY_LIMIT = "E010"
ERR_INPUT_READ_FAILED = "E011"
ERR_INTERNAL_ERROR = "E099"
