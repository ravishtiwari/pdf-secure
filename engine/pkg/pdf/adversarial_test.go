package pdf

import (
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

// TestAdversarialInputs verifies the engine returns error receipts (and does
// not panic) for malformed or out-of-bounds inputs.
// TODO: add an already-encrypted PDF case once a fixture is available.
func TestAdversarialInputs(t *testing.T) {
	minimalPDF, err := os.ReadFile("../../testdata/minimal.pdf")
	if err != nil {
		t.Fatalf("Failed to read minimal.pdf fixture: %v", err)
	}

	// padToSize returns minimal.pdf content padded with trailing bytes
	// (after %%EOF, ignored by parsers) up to exactly n bytes.
	padToSize := func(n int) []byte {
		if n < len(minimalPDF) {
			t.Fatalf("pad size %d smaller than fixture %d", n, len(minimalPDF))
		}
		out := make([]byte, n)
		copy(out, minimalPDF)
		for i := len(minimalPDF); i < n; i++ {
			out[i] = '%'
		}
		return out
	}

	const oneMB = 1024 * 1024

	tests := []struct {
		name      string
		content   []byte
		wantOK    bool
		wantCodes []string // acceptable error codes when wantOK is false
	}{
		{
			name:      "zero_byte_file",
			content:   []byte{},
			wantOK:    false,
			wantCodes: []string{receipt.ErrInputPDFInvalid, receipt.ErrInputPDFUnsupported},
		},
		{
			name:      "header_only",
			content:   []byte("%PDF-1.4\n"),
			wantOK:    false,
			wantCodes: []string{receipt.ErrInputPDFInvalid, receipt.ErrInputPDFUnsupported},
		},
		{
			name:    "size_exactly_at_limit",
			content: padToSize(oneMB), // exactly 1 MB with max_input_mb=1
			wantOK:  true,
		},
		{
			name:      "size_one_byte_over_limit",
			content:   padToSize(oneMB + 1),
			wantOK:    false,
			wantCodes: []string{receipt.ErrInputPDFInvalid, receipt.ErrInputPDFUnsupported},
		},
	}

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  "adv-pass",
			CryptoProfile: "strong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			inputPath := filepath.Join(tmpDir, "input.pdf")
			outputPath := filepath.Join(tmpDir, "output.pdf")
			if err := os.WriteFile(inputPath, tt.content, 0o600); err != nil {
				t.Fatalf("Failed to write input: %v", err)
			}

			opts := options.Default()
			opts.MaxInputMB = 1

			proc := NewProcessor(pol, inputPath, outputPath, opts)
			rec, err := proc.Process() // must not panic

			if tt.wantOK {
				if err != nil {
					t.Fatalf("Expected success, got error: %v", err)
				}
				if !rec.OK {
					t.Fatalf("Expected receipt OK, got error: %+v", rec.Error)
				}
				return
			}

			if rec == nil {
				t.Fatal("Expected an error receipt, got nil")
			}
			if rec.OK {
				t.Fatal("Expected receipt OK to be false")
			}
			if rec.Error == nil {
				t.Fatal("Expected receipt error to be set")
			}
			codeOK := false
			for _, c := range tt.wantCodes {
				if rec.Error.Code == c {
					codeOK = true
				}
			}
			if !codeOK {
				t.Errorf("Unexpected error code %s (want one of %v): %s",
					rec.Error.Code, tt.wantCodes, rec.Error.Message)
			}
		})
	}
}
