"""SecurePDF Python SDK.

A Python wrapper for the SecurePDF Go engine providing PDF security operations.
"""

__version__ = "0.0.1"

from .exception import (
    SecurePDFEncryptionError,
    SecurePDFEngineException,
    SecurePDFException,
    SecurePDFInputInvalidError,
    SecurePDFInputReadError,
    SecurePDFInputUnsupportedError,
    SecurePDFInternalError,
    SecurePDFLabelError,
    SecurePDFMemoryLimitError,
    SecurePDFOutputError,
    SecurePDFPolicyInvalidError,
    SecurePDFProvenanceError,
    SecurePDFTamperHashError,
    SecurePDFTimeoutError,
    SecurePDFWeakCryptoRejectedError,
    exception_from_receipt,
)
from .models import (
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
    AckConfig,
    EncryptionConfig,
    InvisibleLabel,
    LabelsConfig,
    # Policy dataclasses
    Policy,
    ProvenanceConfig,
    # Receipt dataclasses
    Receipt,
    ReceiptError,
    ReceiptWarning,
    TamperDetectionConfig,
    VisibleLabel,
)
from .sdk import batch_secure_pdf, secure_pdf

__all__ = [
    # Version
    "__version__",
    # Main functions
    "secure_pdf",
    "batch_secure_pdf",
    # Policy dataclasses
    "Policy",
    "EncryptionConfig",
    "AckConfig",
    "LabelsConfig",
    "VisibleLabel",
    "InvisibleLabel",
    "ProvenanceConfig",
    "TamperDetectionConfig",
    # Receipt dataclasses
    "Receipt",
    "ReceiptWarning",
    "ReceiptError",
    # Warning codes
    "WARN_WEAK_CRYPTO_REQUESTED",
    "WARN_WEAK_CRYPTO_REJECTED",
    "WARN_VIEWER_DEPENDENT_ACK",
    "WARN_UNSUPPORTED_PDF_FEATURE",
    "WARN_LABEL_PARTIALLY_APPLIED",
    "WARN_PROVENANCE_PARTIALLY_APPLIED",
    "WARN_TAMPER_HASH_EMBED_FAILED",
    "WARN_UNKNOWN_POLICY_FIELD",
    # Error codes
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
    # Exceptions
    "SecurePDFException",
    "SecurePDFEngineException",
    "SecurePDFPolicyInvalidError",
    "SecurePDFInputInvalidError",
    "SecurePDFInputUnsupportedError",
    "SecurePDFEncryptionError",
    "SecurePDFLabelError",
    "SecurePDFProvenanceError",
    "SecurePDFTamperHashError",
    "SecurePDFOutputError",
    "SecurePDFTimeoutError",
    "SecurePDFMemoryLimitError",
    "SecurePDFInputReadError",
    "SecurePDFWeakCryptoRejectedError",
    "SecurePDFInternalError",
    "exception_from_receipt",
]
