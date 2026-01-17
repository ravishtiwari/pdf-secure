package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// Golden Tests for Receipt Schema Stability
// =============================================================================
//
// These tests ensure that the receipt schema remains stable and backward
// compatible. They verify:
// 1. All fixtures parse without error
// 2. Required fields are always present
// 3. Schema invariants hold (e.g., ok=true => error=nil)
// 4. JSON round-trips preserve all data
// 5. Generated receipts match expected schema structure

// TestGoldenSuccessReceipts verifies all success receipt fixtures match schema invariants.
func TestGoldenSuccessReceipts(t *testing.T) {
	successDir := "../../testdata/receipts/success"
	files, err := os.ReadDir(successDir)
	if err != nil {
		t.Fatalf("failed to read success directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no success receipt fixtures found - test infrastructure broken")
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			path := filepath.Join(successDir, file.Name())
			verifySuccessReceiptInvariants(t, path)
		})
	}
}

// TestGoldenErrorReceipts verifies all error receipt fixtures match schema invariants.
func TestGoldenErrorReceipts(t *testing.T) {
	errorDir := "../../testdata/receipts/error"
	files, err := os.ReadDir(errorDir)
	if err != nil {
		t.Fatalf("failed to read error directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no error receipt fixtures found - test infrastructure broken")
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			path := filepath.Join(errorDir, file.Name())
			verifyErrorReceiptInvariants(t, path)
		})
	}
}

// TestGoldenReceiptRoundTrip ensures generated receipts can be serialized and deserialized.
func TestGoldenReceiptRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		buildFn  func() *Receipt
		validate func(t *testing.T, r *Receipt)
	}{
		{
			name: "minimal success",
			buildFn: func() *Receipt {
				return NewSuccess("0.0.1", "1.0")
			},
			validate: func(t *testing.T, r *Receipt) {
				if !r.OK {
					t.Error("expected ok=true")
				}
				if r.Error != nil {
					t.Error("expected error=nil")
				}
			},
		},
		{
			name: "success with provenance",
			buildFn: func() *Receipt {
				r := NewSuccess("0.0.1", "1.0")
				r.SetProvenance("doc-abc", "copy-xyz")
				return r
			},
			validate: func(t *testing.T, r *Receipt) {
				if r.DocumentID != "doc-abc" {
					t.Errorf("expected document_id=doc-abc, got %s", r.DocumentID)
				}
				if r.CopyID != "copy-xyz" {
					t.Errorf("expected copy_id=copy-xyz, got %s", r.CopyID)
				}
			},
		},
		{
			name: "success with warnings",
			buildFn: func() *Receipt {
				r := NewSuccess("0.0.1", "1.0")
				r.AddWarning(WarnWeakCryptoRequested, "Legacy crypto requested")
				r.AddWarning(WarnViewerDependentAck, "Ack is viewer-dependent")
				return r
			},
			validate: func(t *testing.T, r *Receipt) {
				if len(r.Warnings) != 2 {
					t.Errorf("expected 2 warnings, got %d", len(r.Warnings))
				}
				if r.Warnings[0].Code != WarnWeakCryptoRequested {
					t.Errorf("expected first warning %s, got %s", WarnWeakCryptoRequested, r.Warnings[0].Code)
				}
			},
		},
		{
			name: "success with hashes",
			buildFn: func() *Receipt {
				r := NewSuccess("0.0.1", "1.0")
				r.SetHashes("abc123", "def456")
				r.SetContentHash("ghi789")
				return r
			},
			validate: func(t *testing.T, r *Receipt) {
				if r.InputSHA256 != "abc123" {
					t.Errorf("expected input_sha256=abc123, got %s", r.InputSHA256)
				}
				if r.OutputSHA256 != "def456" {
					t.Errorf("expected output_sha256=def456, got %s", r.OutputSHA256)
				}
				if r.InputContentHash != "ghi789" {
					t.Errorf("expected input_content_hash=ghi789, got %s", r.InputContentHash)
				}
			},
		},
		{
			name: "error with details",
			buildFn: func() *Receipt {
				return NewErrorWithDetails(
					"0.0.1",
					"1.0",
					ErrPolicyInvalid,
					"Missing password",
					map[string]string{"field": "encryption.user_password"},
				)
			},
			validate: func(t *testing.T, r *Receipt) {
				if r.OK {
					t.Error("expected ok=false")
				}
				if r.Error == nil {
					t.Fatal("expected error to be present")
				}
				if r.Error.Code != ErrPolicyInvalid {
					t.Errorf("expected error.code=%s, got %s", ErrPolicyInvalid, r.Error.Code)
				}
				if r.Error.Details["field"] != "encryption.user_password" {
					t.Errorf("expected details.field=encryption.user_password, got %s", r.Error.Details["field"])
				}
			},
		},
		{
			name: "error with warnings",
			buildFn: func() *Receipt {
				r := NewError("0.0.1", "1.0", ErrRuntimeTimeout, "Operation timed out")
				r.AddWarning(WarnUnsupportedPDFFeature, "PDF has unsupported features")
				return r
			},
			validate: func(t *testing.T, r *Receipt) {
				if r.OK {
					t.Error("expected ok=false")
				}
				if len(r.Warnings) != 1 {
					t.Errorf("expected 1 warning, got %d", len(r.Warnings))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.buildFn()

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

			// Run validation
			tc.validate(t, &loaded)

			// Verify core invariants
			verifyReceiptInvariants(t, &loaded)
		})
	}
}

// TestGoldenSchemaFields ensures all expected fields are present in JSON output.
func TestGoldenSchemaFields(t *testing.T) {
	r := NewSuccess("0.0.1", "1.0")
	r.SetProvenance("doc-test", "copy-test")
	r.SetHashes("input", "output")
	r.SetContentHash("content")
	r.AddWarning(WarnWeakCryptoRequested, "Test")

	data, err := r.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse as map: %v", err)
	}

	// Required fields
	requiredFields := []string{
		"ok",
		"engine_version",
		"policy_version",
		"warnings",
	}

	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("required field %q missing from JSON output", field)
		}
	}

	// Verify warnings is an array, not null
	warnings, ok := raw["warnings"]
	if !ok {
		t.Fatal("warnings field missing")
	}
	if _, ok := warnings.([]interface{}); !ok {
		t.Error("warnings should be an array, not null")
	}

	// Verify error is null for success receipts
	errorVal, hasError := raw["error"]
	if hasError && errorVal != nil {
		t.Error("error should be null for success receipts")
	}
}

// TestGoldenErrorSchemaFields ensures error receipts have proper error structure.
func TestGoldenErrorSchemaFields(t *testing.T) {
	r := NewErrorWithDetails("0.0.1", "1.0", ErrPolicyInvalid, "Test error", map[string]string{"key": "value"})

	data, err := r.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse as map: %v", err)
	}

	// Verify error structure
	errorObj, ok := raw["error"].(map[string]interface{})
	if !ok {
		t.Fatal("error should be an object for error receipts")
	}

	errorFields := []string{"code", "message"}
	for _, field := range errorFields {
		if _, ok := errorObj[field]; !ok {
			t.Errorf("error.%s field missing", field)
		}
	}

	// Verify details is present
	if _, ok := errorObj["details"]; !ok {
		t.Error("error.details should be present when provided")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func verifySuccessReceiptInvariants(t *testing.T, path string) {
	t.Helper()

	r, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	// Invariant: ok=true for success receipts
	if !r.OK {
		t.Error("success receipt must have ok=true")
	}

	// Invariant: error=nil when ok=true
	if r.Error != nil {
		t.Error("success receipt must have error=nil")
	}

	verifyReceiptInvariants(t, r)
}

func verifyErrorReceiptInvariants(t *testing.T, path string) {
	t.Helper()

	r, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	// Invariant: ok=false for error receipts
	if r.OK {
		t.Error("error receipt must have ok=false")
	}

	// Invariant: error!=nil when ok=false
	if r.Error == nil {
		t.Error("error receipt must have error set")
	} else {
		// Invariant: error has code
		if r.Error.Code == "" {
			t.Error("error.code is required")
		}
		// Invariant: error has message
		if r.Error.Message == "" {
			t.Error("error.message is required")
		}
	}

	verifyReceiptInvariants(t, r)
}

func verifyReceiptInvariants(t *testing.T, r *Receipt) {
	t.Helper()

	// Required fields
	if r.EngineVersion == "" {
		t.Error("engine_version is required")
	}
	if r.PolicyVersion == "" {
		t.Error("policy_version is required")
	}
	if r.Warnings == nil {
		t.Error("warnings must be non-nil (empty slice, not null)")
	}
}
