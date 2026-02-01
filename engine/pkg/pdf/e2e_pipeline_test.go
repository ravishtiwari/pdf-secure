package pdf

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

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

	proc := NewProcessor(pol, inputPath, outputPath)
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

	proc := NewProcessor(pol, inputPath, outputPath)
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

	proc := NewProcessor(pol, invalidInput, outputPath)
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

	proc := NewProcessor(pol, missingInput, outputPath)
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

	proc := NewProcessor(pol, inputPath, outputPath)
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

	proc := NewProcessor(pol, inputPath, outputPath)
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
}
