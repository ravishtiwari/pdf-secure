package pdf

import (
	"path/filepath"
	"testing"

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
