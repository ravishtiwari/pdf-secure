class SecurePDFException(Exception):
    pass


class SecurePDFPolicyException(SecurePDFException):
    pass


class SecurePDFReceiptException(SecurePDFException):
    pass


class SecurePDFEngineException(SecurePDFException):
    pass


class SecurePDFSDKException(SecurePDFException):
    pass


class SecurePDFPolicyInvalidError(SecurePDFException):
    """Raised when policy is invalid or malformed (E001)."""

    pass


class SecurePDFInputInvalidError(SecurePDFException):
    """Raised when input PDF is invalid or corrupted (E002)."""

    pass


class SecurePDFInputUnsupportedError(SecurePDFException):
    """Raised when input PDF uses unsupported features (E003)."""

    pass


class SecurePDFEncryptionError(SecurePDFException):
    """Raised when PDF encryption fails (E004)."""

    pass


class SecurePDFLabelError(SecurePDFException):
    """Raised when label application fails (E005)."""

    pass


class SecurePDFProvenanceError(SecurePDFException):
    """Raised when provenance embedding fails (E006)."""

    pass


class SecurePDFTamperHashError(SecurePDFException):
    """Raised when tamper detection hash computation fails (E007)."""

    pass


class SecurePDFOutputError(SecurePDFException):
    """Raised when output file cannot be written (E008)."""

    pass


class SecurePDFTimeoutError(SecurePDFException):
    """Raised when transformation exceeds timeout (E009)."""

    pass


class SecurePDFMemoryLimitError(SecurePDFException):
    """Raised when transformation exceeds memory limit (E010)."""

    pass


class SecurePDFInputReadError(SecurePDFException):
    """Raised when input file cannot be read (E011)."""

    pass


class SecurePDFWeakCryptoRejectedError(SecurePDFException):
    """Raised when weak crypto is rejected by engine (E012)."""

    pass


class SecurePDFInternalError(SecurePDFException):
    """Raised for unexpected internal errors (E099)."""

    pass


def exception_from_receipt(receipt):
    """
    Create a specific exception from a receipt's error code.

    Args:
        receipt: Receipt object with error details

    Returns:
        Appropriate exception instance based on error code
    """
    if receipt.ok:
        return None

    if not receipt.error:
        return SecurePDFException(
            "Unknown error: receipt.ok=false but no error details"
        )

    error_code = receipt.error.code
    message = receipt.error.message or "No error message provided"

    # Map error codes to exception classes
    error_map = {
        "E001": SecurePDFPolicyInvalidError,
        "E002": SecurePDFInputInvalidError,
        "E003": SecurePDFInputUnsupportedError,
        "E004": SecurePDFEncryptionError,
        "E005": SecurePDFLabelError,
        "E006": SecurePDFProvenanceError,
        "E007": SecurePDFTamperHashError,
        "E008": SecurePDFOutputError,
        "E009": SecurePDFTimeoutError,
        "E010": SecurePDFMemoryLimitError,
        "E011": SecurePDFInputReadError,
        "E012": SecurePDFWeakCryptoRejectedError,
        "E099": SecurePDFInternalError,
    }

    exception_class = error_map.get(error_code, SecurePDFException)
    return exception_class(message)
