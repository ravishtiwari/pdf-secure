package pdf

import (
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/policy"
)

// BenchmarkProcessorSecure benchmarks the full pipeline (validate, hash,
// labels, provenance, tamper detection, encrypt) on the minimal fixture.
func BenchmarkProcessorSecure(b *testing.B) {
	inputPath := "../../testdata/minimal.pdf"
	tmpDir := b.TempDir()

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  "bench-pass",
			CryptoProfile: "strong",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench-out.pdf")
		proc := NewProcessor(pol, inputPath, outputPath, nil)
		rec, err := proc.Process()
		if err != nil {
			b.Fatalf("Process failed: %v", err)
		}
		if !rec.OK {
			b.Fatal("Expected receipt OK to be true")
		}
	}
}
