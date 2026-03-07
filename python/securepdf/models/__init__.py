"""SecurePDF Models Package."""

from .codes import (
    ERR_ENCRYPTION_FAILED,
    ERR_INPUT_PDF_INVALID,
    ERR_INPUT_PDF_UNSUPPORTED,
    ERR_INPUT_READ_FAILED,
    ERR_INTERNAL_ERROR,
    ERR_LABEL_FAILED,
    ERR_OUTPUT_WRITE_FAILED,
    # Error codes
    ERR_POLICY_INVALID,
    ERR_PROVENANCE_FAILED,
    ERR_RUNTIME_MEMORY_LIMIT,
    ERR_RUNTIME_TIMEOUT,
    ERR_TAMPER_HASH_FAILED,
    WARN_LABEL_PARTIALLY_APPLIED,
    WARN_PROVENANCE_PARTIALLY_APPLIED,
    WARN_TAMPER_HASH_EMBED_FAILED,
    WARN_UNKNOWN_POLICY_FIELD,
    WARN_UNSUPPORTED_PDF_FEATURE,
    WARN_VIEWER_DEPENDENT_ACK,
    WARN_WEAK_CRYPTO_REJECTED,
    # Warning codes
    WARN_WEAK_CRYPTO_REQUESTED,
)
from .policy import (
    AckConfig,
    EncryptionConfig,
    InvisibleLabel,
    LabelsConfig,
    Policy,
    ProvenanceConfig,
    TamperDetectionConfig,
    VisibleLabel,
)
from .receipt import (
    Receipt,
    ReceiptError,
    ReceiptWarning,
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
