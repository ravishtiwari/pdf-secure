"""SecurePDF Models Package."""

from .codes import (
    # Warning codes
    WARN_WEAK_CRYPTO_REQUESTED,
    WARN_WEAK_CRYPTO_REJECTED,
    WARN_VIEWER_DEPENDENT_ACK,
    WARN_UNSUPPORTED_PDF_FEATURE,
    WARN_LABEL_PARTIALLY_APPLIED,
    WARN_PROVENANCE_PARTIALLY_APPLIED,
    WARN_TAMPER_HASH_EMBED_FAILED,
    WARN_UNKNOWN_POLICY_FIELD,
    # Error codes
    ERR_POLICY_INVALID,
    ERR_INPUT_PDF_INVALID,
    ERR_INPUT_PDF_UNSUPPORTED,
    ERR_ENCRYPTION_FAILED,
    ERR_LABEL_FAILED,
    ERR_PROVENANCE_FAILED,
    ERR_TAMPER_HASH_FAILED,
    ERR_OUTPUT_WRITE_FAILED,
    ERR_RUNTIME_TIMEOUT,
    ERR_RUNTIME_MEMORY_LIMIT,
    ERR_INPUT_READ_FAILED,
    ERR_INTERNAL_ERROR,
)
from .policy import (
    Policy,
    EncryptionConfig,
    AckConfig,
    LabelsConfig,
    VisibleLabel,
    InvisibleLabel,
    ProvenanceConfig,
    TamperDetectionConfig,
)
from .receipt import (
    Receipt,
    ReceiptWarning,
    ReceiptError,
)

__all__ = [
    # Policy
    "Policy",
    "EncryptionConfig",
    "AckConfig",
    "LabelsConfig",
    "VisibleLabel",
    "InvisibleLabel",
    "ProvenanceConfig",
    "TamperDetectionConfig",
    # Receipt
    "Receipt",
    "ReceiptWarning",
    "ReceiptError",
    # Codes
    "WARN_WEAK_CRYPTO_REQUESTED",
    "WARN_WEAK_CRYPTO_REJECTED",
    "WARN_VIEWER_DEPENDENT_ACK",
    "WARN_UNSUPPORTED_PDF_FEATURE",
    "WARN_LABEL_PARTIALLY_APPLIED",
    "WARN_PROVENANCE_PARTIALLY_APPLIED",
    "WARN_TAMPER_HASH_EMBED_FAILED",
    "WARN_UNKNOWN_POLICY_FIELD",
    "ERR_POLICY_INVALID",
    "ERR_INPUT_PDF_INVALID",
    "ERR_INPUT_PDF_UNSUPPORTED",
    "ERR_ENCRYPTION_FAILED",
    "ERR_LABEL_FAILED",
    "ERR_PROVENANCE_FAILED",
    "ERR_TAMPER_HASH_FAILED",
    "ERR_OUTPUT_WRITE_FAILED",
    "ERR_RUNTIME_TIMEOUT",
    "ERR_RUNTIME_MEMORY_LIMIT",
    "ERR_INPUT_READ_FAILED",
    "ERR_INTERNAL_ERROR",
]
