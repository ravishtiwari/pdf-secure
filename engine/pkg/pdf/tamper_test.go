package pdf

import (
	"path/filepath"
	"strings"
	"testing"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
)

func TestApplyTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "tamper.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	config := &policy.TamperDetectionConfig{
		Enabled: true,
		HashAlg: "sha256",
	}

	result, err := ApplyTamperDetection(outputPath, config)
	if err != nil {
		t.Fatalf("ApplyTamperDetection failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.ContentHash == "" {
		t.Error("Expected ContentHash to be set")
	}
}

func TestApplyTamperDetectionInvalidAlg(t *testing.T) {
	config := &policy.TamperDetectionConfig{
		Enabled: true,
		HashAlg: "md5",
	}

	_, err := ApplyTamperDetection("dummy.pdf", config)
	if err == nil {
		t.Error("Expected error for unsupported hash algorithm")
	}
}

func TestApplyTamperDetectionProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{name: "content_streams", profile: consts.HashProfileContentStreams},
		{name: "external", profile: consts.HashProfileExternal},
		{name: "unknown_defaults_to_objects_only", profile: "unknown-profile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "tamper-profile.pdf")

			if err := copyFileHelper("../../test-pdfs/sample-input.pdf", outputPath); err != nil {
				t.Fatalf("Failed to copy input: %v", err)
			}

			result, err := ApplyTamperDetection(outputPath, &policy.TamperDetectionConfig{
				Enabled:     true,
				HashAlg:     "sha256",
				HashProfile: tt.profile,
			})
			if err != nil {
				t.Fatalf("ApplyTamperDetection failed: %v", err)
			}
			if !result.Success {
				t.Fatal("expected success")
			}
			if result.ContentHash == "" {
				t.Fatal("expected content hash to be populated")
			}
		})
	}
}

func TestApplyTamperDetectionDisabled(t *testing.T) {
	config := &policy.TamperDetectionConfig{Enabled: false}
	result, err := ApplyTamperDetection("dummy.pdf", config)
	if err != nil {
		t.Fatalf("ApplyTamperDetection failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.ContentHash != "" {
		t.Error("Expected no content hash when disabled")
	}
}

func TestTamperDetectionVerifyUnmodified(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	workingPath := filepath.Join(tmpDir, "tamper-verify.pdf")

	if err := copyFileHelper(inputPath, workingPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Apply tamper detection
	config := &policy.TamperDetectionConfig{
		Enabled: true,
		HashAlg: "sha256",
	}

	result, err := ApplyTamperDetection(workingPath, config)
	if err != nil {
		t.Fatalf("ApplyTamperDetection failed: %v", err)
	}
	if !result.Success || result.ContentHash == "" {
		t.Fatal("Tamper detection setup failed")
	}

	// Verify: unmodified PDF should pass verification
	valid, err := VerifyTamperDetection(workingPath)
	if err != nil {
		t.Fatalf("VerifyTamperDetection failed: %v", err)
	}
	if !valid {
		t.Error("Expected tamper detection to pass on unmodified PDF")
	}
}

func TestTamperDetectionVerifyModified(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	workingPath := filepath.Join(tmpDir, "tamper-modified.pdf")

	if err := copyFileHelper(inputPath, workingPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Apply tamper detection
	config := &policy.TamperDetectionConfig{
		Enabled: true,
		HashAlg: "sha256",
	}

	result, err := ApplyTamperDetection(workingPath, config)
	if err != nil {
		t.Fatalf("ApplyTamperDetection failed: %v", err)
	}
	if !result.Success || result.ContentHash == "" {
		t.Fatal("Tamper detection setup failed")
	}

	// Modify the PDF by applying a visible label (watermark), which changes content objects
	labelConfig := &policy.VisibleLabel{
		Text:      "TAMPERED",
		Placement: "footer",
		Pages:     "all",
	}
	_, err = ApplyVisibleLabel(workingPath, labelConfig)
	if err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	// Verify: modified PDF should FAIL verification
	valid, err := VerifyTamperDetection(workingPath)
	if err != nil {
		t.Fatalf("VerifyTamperDetection returned error: %v", err)
	}
	if valid {
		t.Error("Expected tamper detection to FAIL on modified PDF, but it passed")
	}
}

func TestVerifyTamperDetectionWithoutEmbeddedHash(t *testing.T) {
	valid, err := VerifyTamperDetection("../../test-pdfs/sample-input.pdf")
	if err == nil {
		t.Fatal("expected VerifyTamperDetection to fail without embedded hash")
	}
	if valid {
		t.Fatal("expected verification to be false without embedded hash")
	}
	if !strings.Contains(err.Error(), "embedded content hash") && !strings.Contains(err.Error(), "no info dictionary found") {
		t.Fatalf("expected missing-hash error, got %v", err)
	}
}
