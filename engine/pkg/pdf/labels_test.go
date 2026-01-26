package pdf

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/policy"
)

func TestApplyVisibleLabelFooter(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "labeled-footer.pdf")

	// Copy input to output (simulate pipeline)
	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Config
	label := &policy.VisibleLabel{
		Text:      "CONFIDENTIAL",
		Placement: "footer",
		Pages:     "all",
	}

	// Execute
	result, err := ApplyVisibleLabel(outputPath, label)
	if err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Error != nil {
		t.Errorf("Expected no error, got: %v", result.Error)
	}
}

func TestApplyVisibleLabelHeader(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "labeled-header.pdf")

	// Copy input to output (simulate pipeline)
	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	// Config
	label := &policy.VisibleLabel{
		Text:      "OFFICIAL",
		Placement: "header",
		Pages:     "all",
	}

	// Execute
	result, err := ApplyVisibleLabel(outputPath, label)
	if err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestApplyVisibleLabelFirstPage(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "labeled-first.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	label := &policy.VisibleLabel{
		Text:      "FIRST PAGE",
		Placement: "footer",
		Pages:     "first",
	}

	result, err := ApplyVisibleLabel(outputPath, label)
	if err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestApplyVisibleLabelPageRange(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "labeled-range.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	label := &policy.VisibleLabel{
		Text:      "PAGES 1-2",
		Placement: "footer",
		Pages:     "range",
		PageRange: "1-2",
	}

	result, err := ApplyVisibleLabel(outputPath, label)
	if err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestApplyVisibleLabelInvalidRange(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "labeled-invalid.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	label := &policy.VisibleLabel{
		Text:      "INVALID",
		Placement: "footer",
		Pages:     "range",
		PageRange: "", // Missing range
	}

	_, err := ApplyVisibleLabel(outputPath, label)
	if err == nil {
		t.Error("Expected error for missing page range")
	}
}

// Helper to copy file for test
func copyFileHelper(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
