// Package receipt defines the receipt schema and error/warning codes for SecurePDF transformations.
package receipt

// =============================================================================
// Warning Codes
// =============================================================================

// Warning codes are used to indicate non-fatal issues during transformation.
// They are prefixed with "W" followed by a 3-digit number.
const (
	// WarnWeakCryptoRequested indicates a weak crypto profile was requested.
	// The transformation proceeds but with reduced security.
	WarnWeakCryptoRequested = "W001"

	// WarnWeakCryptoRejected indicates a weak crypto profile was requested
	// but rejected due to engine options (reject_weak_crypto=true).
	WarnWeakCryptoRejected = "W002"

	// WarnViewerDependentAck indicates the acknowledgment mechanism is
	// viewer-dependent and may not work in all PDF viewers.
	WarnViewerDependentAck = "W003"

	// WarnUnsupportedPDFFeature indicates the input PDF contains features
	// that may not be fully preserved or handled correctly.
	WarnUnsupportedPDFFeature = "W004"

	// WarnLabelPartiallyApplied indicates visible labels could not be
	// applied to all requested pages (e.g., some pages have incompatible content).
	WarnLabelPartiallyApplied = "W005"

	// WarnProvenancePartiallyApplied indicates provenance data could not
	// be fully embedded (e.g., limited metadata space).
	WarnProvenancePartiallyApplied = "W006"

	// WarnTamperHashEmbedFailed indicates the tamper detection hash
	// was computed but could not be embedded in the PDF metadata.
	WarnTamperHashEmbedFailed = "W007"

	// WarnUnknownPolicyField indicates the policy contained unknown fields
	// that were ignored (forward compatibility).
	WarnUnknownPolicyField = "W008"
)

// warningMessages maps warning codes to their human-readable descriptions.
var warningMessages = map[string]string{
	WarnWeakCryptoRequested:        "Weak cryptography profile requested; proceeding with reduced security",
	WarnWeakCryptoRejected:         "Weak cryptography profile rejected by engine configuration",
	WarnViewerDependentAck:         "Acknowledgment mechanism is viewer-dependent and may not display in all viewers",
	WarnUnsupportedPDFFeature:      "Input PDF contains unsupported features that may not be fully preserved",
	WarnLabelPartiallyApplied:      "Labels could not be applied to all requested pages",
	WarnProvenancePartiallyApplied: "Provenance data could not be fully embedded",
	WarnTamperHashEmbedFailed:      "Tamper detection hash computed but could not be embedded in metadata",
	WarnUnknownPolicyField:         "Policy contained unknown fields that were ignored",
}

// =============================================================================
// Error Codes
// =============================================================================

// Error codes are used to indicate fatal issues that prevent transformation.
// They are prefixed with "E" followed by a 3-digit number.
const (
	// ErrPolicyInvalid indicates the policy JSON was malformed or invalid.
	ErrPolicyInvalid = "E001"

	// ErrInputPDFInvalid indicates the input file is not a valid PDF.
	ErrInputPDFInvalid = "E002"

	// ErrInputPDFUnsupported indicates the input PDF uses features
	// that the engine cannot process.
	ErrInputPDFUnsupported = "E003"

	// ErrEncryptionFailed indicates PDF encryption failed.
	ErrEncryptionFailed = "E004"

	// ErrLabelFailed indicates label application failed completely.
	ErrLabelFailed = "E005"

	// ErrProvenanceFailed indicates provenance embedding failed completely.
	ErrProvenanceFailed = "E006"

	// ErrTamperHashFailed indicates tamper detection hash computation failed.
	ErrTamperHashFailed = "E007"

	// ErrOutputWriteFailed indicates the output file could not be written.
	ErrOutputWriteFailed = "E008"

	// ErrRuntimeTimeout indicates the transformation exceeded the time limit.
	ErrRuntimeTimeout = "E009"

	// ErrRuntimeMemoryLimit indicates the transformation exceeded the memory limit.
	ErrRuntimeMemoryLimit = "E010"

	// ErrInputReadFailed indicates the input file could not be read.
	ErrInputReadFailed = "E011"

	// ErrWeakCryptoRejected indicates a weak crypto profile was requested
	// but rejected due to engine options (reject_weak_crypto=true).
	ErrWeakCryptoRejected = "E012"

	// ErrInternalError indicates an unexpected internal error.
	ErrInternalError = "E099"
)

// errorMessages maps error codes to their human-readable descriptions.
var errorMessages = map[string]string{
	ErrPolicyInvalid:       "Policy is invalid or malformed",
	ErrInputPDFInvalid:     "Input file is not a valid PDF",
	ErrInputPDFUnsupported: "Input PDF uses unsupported features",
	ErrEncryptionFailed:    "PDF encryption failed",
	ErrLabelFailed:         "Label application failed",
	ErrProvenanceFailed:    "Provenance embedding failed",
	ErrTamperHashFailed:    "Tamper detection hash computation failed",
	ErrOutputWriteFailed:   "Output file could not be written",
	ErrRuntimeTimeout:      "Transformation exceeded time limit",
	ErrRuntimeMemoryLimit:  "Transformation exceeded memory limit",
	ErrInputReadFailed:     "Input file could not be read",
	ErrWeakCryptoRejected:  "Weak cryptography profile rejected by engine configuration",
	ErrInternalError:       "Unexpected internal error",
}

// =============================================================================
// Exit Codes (matching CLI contract)
// =============================================================================

// Exit codes for the CLI, matching engine-contract.md.
const (
	ExitSuccess         = 0 // Transformation completed successfully (ok=true)
	ExitPolicyInvalid   = 2 // Policy is invalid
	ExitInputInvalid    = 3 // Input PDF is invalid or unsupported
	ExitTransformFailed = 4 // Transformation failed
	ExitOutputFailed    = 5 // Output write failed
	ExitRuntimeLimit    = 6 // Runtime limit exceeded (timeout/memory)
)

// errorToExitCode maps error codes to CLI exit codes.
var errorToExitCode = map[string]int{
	ErrPolicyInvalid:       ExitPolicyInvalid,
	ErrInputPDFInvalid:     ExitInputInvalid,
	ErrInputPDFUnsupported: ExitInputInvalid,
	ErrEncryptionFailed:    ExitTransformFailed,
	ErrLabelFailed:         ExitTransformFailed,
	ErrProvenanceFailed:    ExitTransformFailed,
	ErrTamperHashFailed:    ExitTransformFailed,
	ErrOutputWriteFailed:   ExitOutputFailed,
	ErrRuntimeTimeout:      ExitRuntimeLimit,
	ErrRuntimeMemoryLimit:  ExitRuntimeLimit,
	ErrInputReadFailed:     ExitInputInvalid,
	ErrWeakCryptoRejected:  ExitTransformFailed,
	ErrInternalError:       ExitTransformFailed,
}

// WarningMessage returns the default message for a warning code.
func WarningMessage(code string) (string, bool) {
	message, ok := warningMessages[code]
	return message, ok
}

// ErrorMessage returns the default message for an error code.
func ErrorMessage(code string) (string, bool) {
	message, ok := errorMessages[code]
	return message, ok
}

// ExitCodeForError returns the CLI exit code for an error code.
func ExitCodeForError(code string) (int, bool) {
	exitCode, ok := errorToExitCode[code]
	return exitCode, ok
}
