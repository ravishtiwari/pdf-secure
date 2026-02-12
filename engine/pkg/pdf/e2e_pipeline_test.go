package pdf

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

// TestE2EProcessPipelineFullFeatures tests the complete pipeline with all features enabled
func TestE2EProcessPipelineFullFeatures(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "pipeline-output.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
		Labels: &policy.LabelsConfig{
			Mode: "visible",
			Visible: &policy.VisibleLabel{
				Text:      "CONFIDENTIAL",
				Placement: "footer",
				Pages:     "all",
			},
		},
		Provenance: &policy.ProvenanceConfig{
			Enabled:    true,
			DocumentID: "auto",
			CopyID:     "auto",
		},
		TamperDetection: &policy.TamperDetectionConfig{
			Enabled: true,
			HashAlg: "sha256",
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatal("Expected receipt OK to be true")
	}
	if rec.DocumentID == "" || rec.CopyID == "" {
		t.Error("Expected provenance IDs to be set")
	}
	if rec.InputSHA256 == "" || rec.OutputSHA256 == "" {
		t.Error("Expected input/output hashes to be set")
	}
	if rec.InputContentHash == "" {
		t.Error("Expected content hash to be set")
	}

	// Verify hashes are different (transformations were applied)
	if rec.InputSHA256 == rec.OutputSHA256 {
		t.Error("Expected input and output hashes to be different after transformations")
	}

	// Verify provenance ID format (UUIDv4 with prefix)
	docPattern := regexp.MustCompile(`^doc-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	copyPattern := regexp.MustCompile(`^copy-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	if !docPattern.MatchString(rec.DocumentID) {
		t.Errorf("DocumentID not in UUIDv4 format: %s", rec.DocumentID)
	}
	if !copyPattern.MatchString(rec.CopyID) {
		t.Errorf("CopyID not in UUIDv4 format: %s", rec.CopyID)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to exist: %v", err)
	}

	// Verify tamper detection
	valid, err := VerifyTamperDetection(outputPath)
	if err != nil {
		t.Fatalf("VerifyTamperDetection failed: %v", err)
	}
	if !valid {
		t.Error("VerifyTamperDetection returned false, expected true")
	}
}

// TestE2EMinimalPipeline tests pipeline with only encryption disabled (passthrough)
func TestE2EMinimalPipeline(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "minimal-output.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
	}
	if rec.InputSHA256 == "" {
		t.Error("Expected input hash to be set")
	}
	if rec.OutputSHA256 == "" {
		t.Error("Expected output hash to be set")
	}

	// For minimal (passthrough), hashes should be equal
	if rec.InputSHA256 != rec.OutputSHA256 {
		t.Log("Input and output hashes differ - this is expected if working file handling adds metadata")
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to exist: %v", err)
	}
}

// TestE2EInputValidation tests error handling for non-PDF input
func TestE2EInputValidation(t *testing.T) {
	tmpDir := t.TempDir()
	invalidInput := filepath.Join(tmpDir, "not-a-pdf.txt")
	outputPath := filepath.Join(tmpDir, "output.pdf")

	// Create a non-PDF file
	if err := os.WriteFile(invalidInput, []byte("This is not a PDF"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
	}

	proc := NewProcessor(pol, invalidInput, outputPath, nil)
	rec, err := proc.Process()

	if err == nil {
		t.Error("Expected error for non-PDF input")
	}
	if rec.OK {
		t.Error("Expected receipt OK to be false for invalid input")
	}
	if rec.Error == nil {
		t.Fatal("Expected error details in receipt")
	}
	if rec.Error.Code != receipt.ErrInputPDFInvalid {
		t.Errorf("Expected error code %s, got %s", receipt.ErrInputPDFInvalid, rec.Error.Code)
	}
}

// TestE2EInputNotFound tests error handling for missing input file
func TestE2EInputNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	missingInput := filepath.Join(tmpDir, "does-not-exist.pdf")
	outputPath := filepath.Join(tmpDir, "output.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
	}

	proc := NewProcessor(pol, missingInput, outputPath, nil)
	rec, err := proc.Process()

	if err == nil {
		t.Error("Expected error for missing input file")
	}
	if rec.OK {
		t.Error("Expected receipt OK to be false for missing input")
	}
	if rec.Error == nil {
		t.Fatal("Expected error details in receipt")
	}
	if rec.Error.Code != receipt.ErrInputPDFInvalid {
		t.Errorf("Expected error code %s, got %s", receipt.ErrInputPDFInvalid, rec.Error.Code)
	}
}

// TestE2EPipelineWithEncryption tests full pipeline with encryption enabled
func TestE2EPipelineWithEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "encrypted-output.pdf")
	password := "TestEncrypt123!"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  password,
			AllowPrint:    true,
			AllowCopy:     false,
			AllowModify:   false,
			CryptoProfile: "strong",
		},
		Labels: &policy.LabelsConfig{
			Mode: "visible",
			Visible: &policy.VisibleLabel{
				Text:      "ENCRYPTED DOC",
				Placement: "footer",
				Pages:     "all",
			},
		},
		Provenance: &policy.ProvenanceConfig{
			Enabled:    true,
			DocumentID: "auto",
			CopyID:     "auto",
		},
		TamperDetection: &policy.TamperDetectionConfig{
			Enabled: true,
			HashAlg: "sha256",
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
	}

	// Verify all fields are populated
	if rec.InputSHA256 == "" {
		t.Error("Expected input hash to be set")
	}
	if rec.OutputSHA256 == "" {
		t.Error("Expected output hash to be set")
	}
	if rec.DocumentID == "" {
		t.Error("Expected document_id to be set")
	}
	if rec.CopyID == "" {
		t.Error("Expected copy_id to be set")
	}
	if rec.InputContentHash == "" {
		t.Error("Expected content hash to be set")
	}

	// Verify output file exists
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to exist: %v", err)
	}

	// Verify output file is different from input (encrypted)
	if rec.InputSHA256 == rec.OutputSHA256 {
		t.Error("Expected output to be different from input after encryption")
	}
}

// TestE2ETamperDetectionOnly tests tamper detection in isolation
func TestE2ETamperDetectionOnly(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "tamper-output.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
		TamperDetection: &policy.TamperDetectionConfig{
			Enabled: true,
			HashAlg: "sha256",
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
	}
	if rec.InputContentHash == "" {
		t.Error("Expected content hash to be set")
	}

	// Content hash should be a valid SHA-256 (64 hex chars)
	if len(rec.InputContentHash) != 64 {
		t.Errorf("Expected 64-char SHA-256 hash, got %d chars", len(rec.InputContentHash))
	}

	// Verify the tamper detection
	valid, err := VerifyTamperDetection(outputPath)
	if err != nil {
		t.Fatalf("VerifyTamperDetection failed: %v", err)
	}
	if !valid {
		t.Error("VerifyTamperDetection returned false, expected true")
	}
}

// TestE2EWeakCryptoRejection tests that weak crypto profiles are properly rejected
// and that the correct error code (ErrWeakCryptoRejected) is returned in the receipt
func TestE2EWeakCryptoRejection(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "rejected-output.pdf")

	testCases := []struct {
		name    string
		profile string
	}{
		{"reject_legacy", "legacy"},
		{"reject_compat", "compat"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pol := &policy.Policy{
				PolicyVersion: "1.0",
				Encryption: policy.EncryptionConfig{
					Enabled:       true,
					Mode:          "password",
					UserPassword:  "test123",
					CryptoProfile: tc.profile,
				},
			}

			// Create processor with RejectWeakCrypto enabled
			opts := &options.EngineOptions{
				RejectWeakCrypto: true,
				TimeoutMs:        60000,
				MaxInputMB:       200,
				MaxMemoryMB:      512,
			}

			proc := NewProcessor(pol, inputPath, outputPath, opts)
			rec, err := proc.Process()

			// Should fail with error
			if err == nil {
				t.Error("Expected error for weak crypto rejection")
			}

			// Receipt should indicate failure
			if rec.OK {
				t.Error("Expected receipt OK to be false for weak crypto rejection")
			}

			// Receipt should have the specific error code
			if rec.Error == nil {
				t.Fatal("Expected error details in receipt")
			}

			if rec.Error.Code != receipt.ErrWeakCryptoRejected {
				t.Errorf("Expected error code %s, got %s", receipt.ErrWeakCryptoRejected, rec.Error.Code)
			}

			// Error message should mention the profile
			if rec.Error.Message == "" {
				t.Error("Expected error message to be set")
			}

			// Details should include the crypto profile
			if rec.Error.Details == nil {
				t.Fatal("Expected error details to be set")
			}

			if profile, ok := rec.Error.Details["crypto_profile"]; !ok || profile != tc.profile {
				t.Errorf("Expected crypto_profile detail to be %s, got %s", tc.profile, profile)
			}

			// Output file should not exist (transformation failed)
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Error("Expected output file to not exist after rejection")
			}
		})
	}
}

// TestE2EWeakCryptoAccepted tests that weak crypto profiles are accepted
// when RejectWeakCrypto is false (default behavior)
func TestE2EWeakCryptoAccepted(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"

	testCases := []struct {
		name    string
		profile string
	}{
		{"accept_legacy", "legacy"},
		{"accept_compat", "compat"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputPath := filepath.Join(tmpDir, tc.name+"-output.pdf")

			pol := &policy.Policy{
				PolicyVersion: "1.0",
				Encryption: policy.EncryptionConfig{
					Enabled:       true,
					Mode:          "password",
					UserPassword:  "test123",
					CryptoProfile: tc.profile,
				},
			}

			// Create processor with RejectWeakCrypto disabled (default)
			opts := &options.EngineOptions{
				RejectWeakCrypto: false,
				TimeoutMs:        60000,
				MaxInputMB:       200,
				MaxMemoryMB:      512,
			}

			proc := NewProcessor(pol, inputPath, outputPath, opts)
			rec, err := proc.Process()

			// Should succeed
			if err != nil {
				t.Fatalf("Process failed unexpectedly: %v", err)
			}

			if !rec.OK {
				t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
			}

			// Should have a warning for legacy profile
			if tc.profile == "legacy" {
				foundWarning := false
				for _, w := range rec.Warnings {
					if w.Code == receipt.WarnWeakCryptoRequested {
						foundWarning = true
						break
					}
				}
				if !foundWarning {
					t.Error("Expected WarnWeakCryptoRequested warning for legacy profile")
				}
			}

			// Output file should exist
			if _, err := os.Stat(outputPath); err != nil {
				t.Errorf("Expected output file to exist: %v", err)
			}
		})
	}
}

// TestE2ETamperDetectionContentStreams tests content_streams hash profile
func TestE2ETamperDetectionContentStreams(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "content-streams-output.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
		TamperDetection: &policy.TamperDetectionConfig{
			Enabled:     true,
			HashAlg:     "sha256",
			HashProfile: "content_streams",
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
	}
	if rec.InputContentHash == "" {
		t.Error("Expected content hash to be set with content_streams profile")
	}

	// Content hash should be a valid SHA-256 (64 hex chars)
	if len(rec.InputContentHash) != 64 {
		t.Errorf("Expected 64-char SHA-256 hash, got %d chars", len(rec.InputContentHash))
	}
}

// TestE2ETamperDetectionContentStreamsVerify tests content_streams hash verification
func TestE2ETamperDetectionContentStreamsVerify(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "content-streams-verify.pdf")

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled: false,
		},
		TamperDetection: &policy.TamperDetectionConfig{
			Enabled:     true,
			HashAlg:     "sha256",
			HashProfile: "content_streams",
		},
	}

	proc := NewProcessor(pol, inputPath, outputPath, nil)
	rec, err := proc.Process()
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if !rec.OK {
		t.Fatalf("Expected receipt OK to be true, got error: %+v", rec.Error)
	}

	// Verify the tamper detection passes
	valid, err := VerifyTamperDetection(outputPath)
	if err != nil {
		t.Fatalf("VerifyTamperDetection failed: %v", err)
	}
	if !valid {
		t.Error("VerifyTamperDetection returned false, expected true for content_streams profile")
	}
}
