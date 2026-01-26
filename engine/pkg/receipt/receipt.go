// Package receipt defines the receipt schema for SecurePDF transformations.
package receipt

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// =============================================================================
// V1 Receipt Schema
// =============================================================================

// Warning represents a non-fatal issue that occurred during transformation.
type Warning struct {
	Code    string `json:"code"`    // Warning code (e.g., "W001")
	Message string `json:"message"` // Human-readable message
}

// Error represents a fatal issue that prevented transformation.
// Only present when ok=false.
type Error struct {
	Code    string            `json:"code"`              // Error code (e.g., "E001")
	Message string            `json:"message"`           // Human-readable summary
	Details map[string]string `json:"details,omitempty"` // Additional context (e.g., {"field": "encryption.user_password"})
}

// Receipt represents the result of a SecurePDF transformation (V1 schema).
type Receipt struct {
	// Required fields (always present)
	OK            bool      `json:"ok"`             // true if transformation succeeded
	EngineVersion string    `json:"engine_version"` // Engine version (e.g., "0.0.1")
	PolicyVersion string    `json:"policy_version"` // Policy version used (e.g., "1.0")
	Warnings      []Warning `json:"warnings"`       // Non-fatal issues (empty array if none)
	Error         *Error    `json:"error"`          // Fatal error (null if ok=true)

	// Identification fields (present on success)
	DocumentID string `json:"document_id,omitempty"` // Provenance document ID
	CopyID     string `json:"copy_id,omitempty"`     // Provenance copy ID

	// Hash fields (present on success)
	InputSHA256      string `json:"input_sha256,omitempty"`       // SHA-256 of input file
	OutputSHA256     string `json:"output_sha256,omitempty"`      // SHA-256 of output file
	InputContentHash string `json:"input_content_hash,omitempty"` // Tamper detection hash (embedded in metadata)

	// Metadata fields (optional)
	Timestamp time.Time `json:"timestamp,omitempty"` // When transformation occurred
}

// =============================================================================
// Receipt Builders
// =============================================================================

// NewSuccess creates a successful receipt with required fields.
func NewSuccess(engineVersion, policyVersion string) *Receipt {
	return &Receipt{
		OK:            true,
		EngineVersion: engineVersion,
		PolicyVersion: policyVersion,
		Warnings:      []Warning{},
		Error:         nil,
		Timestamp:     time.Now().UTC(),
	}
}

// NewError creates a failed receipt with the given error.
func NewError(engineVersion, policyVersion, errorCode, errorMessage string) *Receipt {
	return &Receipt{
		OK:            false,
		EngineVersion: engineVersion,
		PolicyVersion: policyVersion,
		Warnings:      []Warning{},
		Error: &Error{
			Code:    errorCode,
			Message: errorMessage,
		},
		Timestamp: time.Now().UTC(),
	}
}

// NewErrorWithDetails creates a failed receipt with error details.
func NewErrorWithDetails(engineVersion, policyVersion, errorCode, errorMessage string, details map[string]string) *Receipt {
	return &Receipt{
		OK:            false,
		EngineVersion: engineVersion,
		PolicyVersion: policyVersion,
		Warnings:      []Warning{},
		Error: &Error{
			Code:    errorCode,
			Message: errorMessage,
			Details: details,
		},
		Timestamp: time.Now().UTC(),
	}
}

// =============================================================================
// Receipt Methods
// =============================================================================

// AddWarning adds a warning to the receipt.
func (r *Receipt) AddWarning(code, message string) {
	r.Warnings = append(r.Warnings, Warning{
		Code:    code,
		Message: message,
	})
}

// AddWarningFromCode adds a warning using a predefined code and its default message.
func (r *Receipt) AddWarningFromCode(code string) {
	message, ok := WarningMessage(code)
	if !ok {
		message = "Unknown warning"
	}
	r.AddWarning(code, message)
}

// SetProvenance sets the document and copy IDs.
func (r *Receipt) SetProvenance(documentID, copyID string) {
	r.DocumentID = documentID
	r.CopyID = copyID
}

// SetHashes sets the input/output SHA-256 hashes.
func (r *Receipt) SetHashes(inputSHA256, outputSHA256 string) {
	r.InputSHA256 = inputSHA256
	r.OutputSHA256 = outputSHA256
}

// SetContentHash sets the tamper detection content hash.
func (r *Receipt) SetContentHash(hash string) {
	r.InputContentHash = hash
}

// GenerateDocumentID generates a new document ID (UUIDv4 with prefix).
func GenerateDocumentID() string {
	return "doc-" + generateUUID()
}

// GenerateCopyID generates a new copy ID (UUIDv4 with prefix).
func GenerateCopyID() string {
	return "copy-" + generateUUID()
}

// GetTimestamp returns the current UTC timestamp in RFC3339 format.
func GetTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// generateUUID generates a random UUID v4 string using stdlib crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("receipt: crypto/rand read failed: %v; falling back to timestamp-based ID", err)
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("fallback-%x", time.Now().UnixNano())
	}
	// Set version (4) and variant (RFC 4122)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// =============================================================================
// Serialization
// =============================================================================

// ToJSON serializes the receipt to a JSON string.
func (r *Receipt) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Save writes the receipt to a JSON file.
func (r *Receipt) Save(path string) error {
	data, err := r.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write receipt file: %w", err)
	}

	return nil
}

// Load reads a receipt from a JSON file.
func Load(path string) (*Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read receipt file: %w", err)
	}

	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("failed to parse receipt: %w", err)
	}

	return &r, nil
}

// =============================================================================
// Legacy Compatibility (deprecated, will be removed in V1.4.x)
// =============================================================================

// Save writes the receipt to a JSON file (legacy function signature).
// Deprecated: Use (*Receipt).Save instead. This function will be removed in v1.4.x
func Save(path string, r *Receipt) error {
	return r.Save(path)
}
