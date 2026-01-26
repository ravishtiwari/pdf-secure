package pdf

import (
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/policy"
)

func TestApplyProvenanceWithAutoIDs(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "provenance-auto.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Config
	config := &policy.ProvenanceConfig{
		Enabled:    true,
		DocumentID: "auto",
		CopyID:     "auto",
	}

	// Execute
	result, err := ApplyProvenance(outputPath, config)
	if err != nil {
		t.Fatalf("ApplyProvenance failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.DocumentID == "" {
		t.Error("Expected DocumentID to be generated")
	}
	if result.CopyID == "" {
		t.Error("Expected CopyID to be generated")
	}
}

func TestApplyProvenanceWithCustomIDs(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "provenance-custom.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Config
	config := &policy.ProvenanceConfig{
		Enabled:    true,
		DocumentID: "custom-doc-id",
		CopyID:     "custom-copy-id",
	}

	// Execute
	result, err := ApplyProvenance(outputPath, config)
	if err != nil {
		t.Fatalf("ApplyProvenance failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.DocumentID != "custom-doc-id" {
		t.Errorf("Expected DocumentID 'custom-doc-id', got '%s'", result.DocumentID)
	}
	if result.CopyID != "custom-copy-id" {
		t.Errorf("Expected CopyID 'custom-copy-id', got '%s'", result.CopyID)
	}
}

func TestProvenanceDisabled(t *testing.T) {
	config := &policy.ProvenanceConfig{Enabled: false}
	result, err := ApplyProvenance("dummy.pdf", config) // File shouldn't be touched
	if err != nil {
		t.Fatalf("ApplyProvenance failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.DocumentID != "" {
		t.Error("Expected no DocumentID when disabled")
	}
}
