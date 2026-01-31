package pdf

import (
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/policy"
)

func TestProcessPipelineE2E(t *testing.T) {
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

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("Expected output file to exist: %v", err)
	}
}
