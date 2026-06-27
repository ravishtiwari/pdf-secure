package pdf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

// readProperties reads the PDF properties map from a file.
func readProperties(t *testing.T, pdfPath string) map[string]string {
	t.Helper()
	f, err := os.Open(pdfPath)
	if err != nil {
		t.Fatalf("Failed to open output PDF: %v", err)
	}
	defer f.Close()
	props, err := api.Properties(f, nil)
	if err != nil {
		t.Fatalf("Failed to read PDF properties: %v", err)
	}
	return props
}

func TestAckEmbedding(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "ack-embed.pdf")

	if err := copyFileHelper(inputPath, outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	config := &policy.AckConfig{
		Required: true,
		Text:     "Custom acknowledgment text",
	}

	result, err := ApplyAcknowledgment(outputPath, config)
	if err != nil {
		t.Fatalf("ApplyAcknowledgment failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}

	props := readProperties(t, outputPath)
	got, ok := props["SecurePDF_Acknowledgment"]
	if !ok {
		t.Fatal("Expected SecurePDF_Acknowledgment property in output PDF")
	}
	if !strings.Contains(got, "Custom acknowledgment text") {
		t.Errorf("Expected custom ack text, got %q", got)
	}
}

func TestAckOSSDefaultFallback(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"oss_default_sentinel", "OSS_DEFAULT"},
		{"empty_text", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "ack-fallback.pdf")
			if err := copyFileHelper("../../test-pdfs/sample-input.pdf", outputPath); err != nil {
				t.Fatalf("Failed to copy input: %v", err)
			}

			config := &policy.AckConfig{
				Required: true,
				Text:     tt.text,
			}

			result, err := ApplyAcknowledgment(outputPath, config)
			if err != nil {
				t.Fatalf("ApplyAcknowledgment failed: %v", err)
			}
			if !result.Success {
				t.Error("Expected Success to be true")
			}

			props := readProperties(t, outputPath)
			got := props["SecurePDF_Acknowledgment"]
			if !strings.Contains(got, ossDefaultAckText) {
				t.Errorf("Expected OSS default ack text for text=%q, got %q", tt.text, got)
			}
		})
	}
}

func TestAckWarningEmitted(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "ack-warning.pdf")
	if err := copyFileHelper("../../test-pdfs/sample-input.pdf", outputPath); err != nil {
		t.Fatalf("Failed to copy input: %v", err)
	}

	config := &policy.AckConfig{
		Required:        true,
		Text:            "OSS_DEFAULT",
		ViewerDependent: true,
	}

	result, err := ApplyAcknowledgment(outputPath, config)
	if err != nil {
		t.Fatalf("ApplyAcknowledgment failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Code == receipt.WarnViewerDependentAck {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected %s warning when ViewerDependent is true", receipt.WarnViewerDependentAck)
	}
}

func TestAckSkippedWhenNotRequired(t *testing.T) {
	result, err := ApplyAcknowledgment("dummy.pdf", &policy.AckConfig{Required: false})
	if err != nil {
		t.Fatalf("ApplyAcknowledgment failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true when ack not required")
	}

	result, err = ApplyAcknowledgment("dummy.pdf", nil)
	if err != nil {
		t.Fatalf("ApplyAcknowledgment failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected Success to be true for nil config")
	}
}
