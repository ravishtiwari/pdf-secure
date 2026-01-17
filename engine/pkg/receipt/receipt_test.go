package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadSuccessReceipts tests loading all success receipt fixtures.
func TestLoadSuccessReceipts(t *testing.T) {
	successDir := "../../testdata/receipts/success"
	files, err := os.ReadDir(successDir)
	if err != nil {
		t.Fatalf("failed to read success directory: %v", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			path := filepath.Join(successDir, file.Name())
			r, err := Load(path)
			if err != nil {
				t.Fatalf("failed to load receipt: %v", err)
			}

			// Verify ok=true for success receipts
			if !r.OK {
				t.Errorf("expected ok=true, got ok=false")
			}

			// Verify error is nil
			if r.Error != nil {
				t.Errorf("expected error=nil for success receipt, got %+v", r.Error)
			}

			// Verify required fields
			if r.EngineVersion == "" {
				t.Error("expected engine_version to be set")
			}
			if r.PolicyVersion == "" {
				t.Error("expected policy_version to be set")
			}
			if r.Warnings == nil {
				t.Error("expected warnings to be non-nil (empty array)")
			}

			t.Logf("loaded success receipt: ok=%v, warnings=%d", r.OK, len(r.Warnings))
		})
	}
}

// TestLoadErrorReceipts tests loading all error receipt fixtures.
func TestLoadErrorReceipts(t *testing.T) {
	errorDir := "../../testdata/receipts/error"
	files, err := os.ReadDir(errorDir)
	if err != nil {
		t.Fatalf("failed to read error directory: %v", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			path := filepath.Join(errorDir, file.Name())
			r, err := Load(path)
			if err != nil {
				t.Fatalf("failed to load receipt: %v", err)
			}

			// Verify ok=false for error receipts
			if r.OK {
				t.Errorf("expected ok=false, got ok=true")
			}

			// Verify error is present
			if r.Error == nil {
				t.Error("expected error to be present for error receipt")
			} else {
				if r.Error.Code == "" {
					t.Error("expected error.code to be set")
				}
				if r.Error.Message == "" {
					t.Error("expected error.message to be set")
				}
			}

			// Verify required fields
			if r.EngineVersion == "" {
				t.Error("expected engine_version to be set")
			}
			if r.PolicyVersion == "" {
				t.Error("expected policy_version to be set")
			}

			t.Logf("loaded error receipt: ok=%v, error=%s", r.OK, r.Error.Code)
		})
	}
}

// TestNewSuccess tests the NewSuccess constructor.
func TestNewSuccess(t *testing.T) {
	r := NewSuccess("1.0.0", "1.0")

	if !r.OK {
		t.Error("expected ok=true")
	}
	if r.EngineVersion != "1.0.0" {
		t.Errorf("expected engine_version=1.0.0, got %s", r.EngineVersion)
	}
	if r.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0, got %s", r.PolicyVersion)
	}
	if r.Warnings == nil {
		t.Error("expected warnings to be initialized")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("expected empty warnings, got %d", len(r.Warnings))
	}
	if r.Error != nil {
		t.Error("expected error=nil")
	}
	if r.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

// TestNewError tests the NewError constructor.
func TestNewError(t *testing.T) {
	r := NewError("1.0.0", "1.0", ErrPolicyInvalid, "test error message")

	if r.OK {
		t.Error("expected ok=false")
	}
	if r.EngineVersion != "1.0.0" {
		t.Errorf("expected engine_version=1.0.0, got %s", r.EngineVersion)
	}
	if r.Error == nil {
		t.Fatal("expected error to be present")
	}
	if r.Error.Code != ErrPolicyInvalid {
		t.Errorf("expected error.code=%s, got %s", ErrPolicyInvalid, r.Error.Code)
	}
	if r.Error.Message != "test error message" {
		t.Errorf("expected error.message='test error message', got '%s'", r.Error.Message)
	}
}

// TestNewErrorWithDetails tests the NewErrorWithDetails constructor.
func TestNewErrorWithDetails(t *testing.T) {
	details := map[string]string{
		"field":  "encryption.user_password",
		"reason": "required",
	}
	r := NewErrorWithDetails("1.0.0", "1.0", ErrPolicyInvalid, "test error", details)

	if r.OK {
		t.Error("expected ok=false")
	}
	if r.Error == nil {
		t.Fatal("expected error to be present")
	}
	if r.Error.Details == nil {
		t.Fatal("expected error.details to be present")
	}
	if r.Error.Details["field"] != "encryption.user_password" {
		t.Errorf("expected details.field='encryption.user_password', got '%s'", r.Error.Details["field"])
	}
}

// TestAddWarning tests adding warnings to a receipt.
func TestAddWarning(t *testing.T) {
	r := NewSuccess("1.0.0", "1.0")

	r.AddWarning(WarnWeakCryptoRequested, "Custom warning message")
	r.AddWarning(WarnViewerDependentAck, "Another warning")

	if len(r.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(r.Warnings))
	}
	if r.Warnings[0].Code != WarnWeakCryptoRequested {
		t.Errorf("expected first warning code=%s, got %s", WarnWeakCryptoRequested, r.Warnings[0].Code)
	}
	if r.Warnings[1].Code != WarnViewerDependentAck {
		t.Errorf("expected second warning code=%s, got %s", WarnViewerDependentAck, r.Warnings[1].Code)
	}
}

// TestAddWarningFromCode tests adding warnings using predefined codes.
func TestAddWarningFromCode(t *testing.T) {
	r := NewSuccess("1.0.0", "1.0")

	r.AddWarningFromCode(WarnWeakCryptoRequested)

	if len(r.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(r.Warnings))
	}
	if r.Warnings[0].Code != WarnWeakCryptoRequested {
		t.Errorf("expected warning code=%s, got %s", WarnWeakCryptoRequested, r.Warnings[0].Code)
	}
	expectedMsg, ok := WarningMessage(WarnWeakCryptoRequested)
	if !ok {
		t.Fatalf("warning code %s not found in warningMessages map", WarnWeakCryptoRequested)
	}
	if r.Warnings[0].Message != expectedMsg {
		t.Errorf("expected warning message='%s', got '%s'", expectedMsg, r.Warnings[0].Message)
	}
}

// TestSetProvenance tests setting provenance IDs.
func TestSetProvenance(t *testing.T) {
	r := NewSuccess("1.0.0", "1.0")

	r.SetProvenance("doc-123", "copy-456")

	if r.DocumentID != "doc-123" {
		t.Errorf("expected document_id=doc-123, got %s", r.DocumentID)
	}
	if r.CopyID != "copy-456" {
		t.Errorf("expected copy_id=copy-456, got %s", r.CopyID)
	}
}

// TestSetHashes tests setting hash values.
func TestSetHashes(t *testing.T) {
	r := NewSuccess("1.0.0", "1.0")

	r.SetHashes("input-sha256", "output-sha256")
	r.SetContentHash("content-hash")

	if r.InputSHA256 != "input-sha256" {
		t.Errorf("expected input_sha256=input-sha256, got %s", r.InputSHA256)
	}
	if r.OutputSHA256 != "output-sha256" {
		t.Errorf("expected output_sha256=output-sha256, got %s", r.OutputSHA256)
	}
	if r.InputContentHash != "content-hash" {
		t.Errorf("expected input_content_hash=content-hash, got %s", r.InputContentHash)
	}
}

// TestGenerateIDs tests ID generation.
func TestGenerateIDs(t *testing.T) {
	docID1 := GenerateDocumentID()
	docID2 := GenerateDocumentID()
	copyID1 := GenerateCopyID()
	copyID2 := GenerateCopyID()

	// Check prefixes
	if !strings.HasPrefix(docID1, "doc-") {
		t.Errorf("expected doc ID to start with 'doc-', got %s", docID1)
	}
	if !strings.HasPrefix(copyID1, "copy-") {
		t.Errorf("expected copy ID to start with 'copy-', got %s", copyID1)
	}

	// Check uniqueness
	if docID1 == docID2 {
		t.Error("expected unique document IDs")
	}
	if copyID1 == copyID2 {
		t.Error("expected unique copy IDs")
	}
}

// TestReceiptJSONRoundTrip tests JSON serialization/deserialization.
func TestReceiptJSONRoundTrip(t *testing.T) {
	original := NewSuccess("1.0.0", "1.0")
	original.SetProvenance("doc-test", "copy-test")
	original.SetHashes("input-hash", "output-hash")
	original.AddWarning(WarnWeakCryptoRequested, "Test warning")

	// Serialize
	data, err := original.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	// Deserialize
	var loaded Receipt
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Verify
	if loaded.OK != original.OK {
		t.Errorf("ok mismatch: %v != %v", loaded.OK, original.OK)
	}
	if loaded.EngineVersion != original.EngineVersion {
		t.Errorf("engine_version mismatch")
	}
	if loaded.DocumentID != original.DocumentID {
		t.Errorf("document_id mismatch")
	}
	if len(loaded.Warnings) != len(original.Warnings) {
		t.Errorf("warnings count mismatch: %d != %d", len(loaded.Warnings), len(original.Warnings))
	}
}

// TestReceiptSaveAndLoad tests file save/load operations.
func TestReceiptSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-receipt.json")

	original := NewSuccess("1.0.0", "1.0")
	original.SetProvenance("doc-save-test", "copy-save-test")

	// Save
	if err := original.Save(path); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Load
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	// Verify
	if loaded.DocumentID != original.DocumentID {
		t.Errorf("document_id mismatch after save/load")
	}
	if loaded.CopyID != original.CopyID {
		t.Errorf("copy_id mismatch after save/load")
	}
}

// TestErrorToExitCode tests error code to exit code mapping.
func TestErrorToExitCode(t *testing.T) {
	tests := []struct {
		errorCode    string
		expectedExit int
	}{
		{ErrPolicyInvalid, ExitPolicyInvalid},
		{ErrInputPDFInvalid, ExitInputInvalid},
		{ErrInputPDFUnsupported, ExitInputInvalid},
		{ErrEncryptionFailed, ExitTransformFailed},
		{ErrOutputWriteFailed, ExitOutputFailed},
		{ErrRuntimeTimeout, ExitRuntimeLimit},
		{ErrRuntimeMemoryLimit, ExitRuntimeLimit},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			exitCode, ok := ExitCodeForError(tt.errorCode)
			if !ok {
				t.Fatalf("error code %s not found in errorToExitCode map", tt.errorCode)
			}
			if exitCode != tt.expectedExit {
				t.Errorf("expected exit code %d for %s, got %d", tt.expectedExit, tt.errorCode, exitCode)
			}
		})
	}
}
