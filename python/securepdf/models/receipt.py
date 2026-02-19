"""Receipt models for SecurePDF V1 schema."""

from dataclasses import dataclass, field
from typing import List, Optional


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
        """Create a Receipt from a dictionary (e.g., from JSON)."""
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

    def to_dict(self) -> dict:
        """Convert receipt to a dictionary."""
        result = {
            "ok": self.ok,
            "engine_version": self.engine_version,
            "policy_version": self.policy_version,
            "warnings": [{"code": w.code, "message": w.message} for w in self.warnings],
        }

        if self.error:
            result["error"] = {
                "code": self.error.code,
                "message": self.error.message,
            }
            if self.error.details:
                result["error"]["details"] = self.error.details

        # Add optional fields if present
        if self.document_id:
            result["document_id"] = self.document_id
        if self.copy_id:
            result["copy_id"] = self.copy_id
        if self.input_sha256:
            result["input_sha256"] = self.input_sha256
        if self.output_sha256:
            result["output_sha256"] = self.output_sha256
        if self.input_content_hash:
            result["input_content_hash"] = self.input_content_hash
        if self.timestamp:
            result["timestamp"] = self.timestamp

        return result
